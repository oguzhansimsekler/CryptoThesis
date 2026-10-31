using CryptoLibrary;
using System.Security.Cryptography;
using Xunit;

namespace KriptoLibrary.Tests;

/// <summary>
/// Each test applies one attack and checks which check rejects the message:
/// the pinned key, the Ed25519 signature, the AEAD tag, or the sequence number.
/// </summary>
public class AttackMatrixTests
{
    private const string IntegrityFailure = "BÜTÜNLÜK HATASI";
    private const string SequenceFailure = "REPLAY SALDIRISI";

    [Fact]
    public void A1_ClientEphemeralKeyTamper_IsAcceptedByServer_ButRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        byte[] tamperedKey = (byte[])client.Session.MyEphemeralPub!.Clone();
        tamperedKey[0] ^= 0xFF; // same change as the hub's "InvalidClientKey" mode

        // X25519 accepts any 32 bytes as a public key, so the server does not fail here.
        ServerHelloMessage hello = ServerRespond(client.Nonce, tamperedKey);

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A2_ClientNonceTamper_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        byte[] tamperedNonce = (byte[])client.Nonce.Clone();
        tamperedNonce[0] ^= 0xFF;

        ServerHelloMessage hello = ServerRespond(tamperedNonce, client.Session.MyEphemeralPub!);

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A3_ServerEphemeralKeySubstitution_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client.Nonce, client.Session.MyEphemeralPub!);

        hello.ServerEphemeralPublicKey = new HandshakeService().GetPublicKey(); // attacker's key

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A4_ServerNonceTamper_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client.Nonce, client.Session.MyEphemeralPub!);

        hello.ServerNonce[0] ^= 0xFF;

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A5_SignatureTamper_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client.Nonce, client.Session.MyEphemeralPub!);

        hello.Signature[0] ^= 0xFF; // same change as the hub's "SignatureTamper" mode

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A6_ServerIdentityKeyTamper_IsRejectedByPinnedKeyCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client.Nonce, client.Session.MyEphemeralPub!);

        hello.ServerIdentityPublicKey[0] ^= 0xFF; // same change as the hub's "PinnedKeyMismatch" mode

        Assert.Equal(ServerHelloVerificationResult.PinnedKeyMismatch, ClientVerify(client, hello));
    }

    [Fact]
    public void A7_ServerImpersonation_WithAttackerSigningKey_IsRejected()
    {
        var client = NewClientHello();
        var attackerIdentity = IdentityService.GenerateLongTermIdentity();
        var attackerSession = new CryptoProtocolSession(attackerIdentity, "Server");
        byte[] serverNonce = RandomNumberGenerator.GetBytes(16);

        // The attacker sends its own identity key and signs the transcript with it.
        ServerHelloMessage ownIdentity = SignHello(attackerIdentity, attackerIdentity.GetPublicKey(),
            client.Nonce, serverNonce, client.Session.MyEphemeralPub!, attackerSession.MyEphemeralPub!);
        Assert.Equal(ServerHelloVerificationResult.PinnedKeyMismatch, ClientVerify(client, ownIdentity));

        // The attacker claims the pinned key but signs with its own key.
        ServerHelloMessage claimedIdentity = SignHello(attackerIdentity, ProtocolIdentity.GetPinnedServerPublicKey(),
            client.Nonce, serverNonce, client.Session.MyEphemeralPub!, attackerSession.MyEphemeralPub!);
        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, claimedIdentity));
    }

    [Fact]
    public void A17_ServerHelloReplayedFromEarlierSession_IsRejectedByClientSignatureCheck()
    {
        var earlierClient = NewClientHello();
        ServerHelloMessage recorded = ServerRespond(earlierClient.Nonce, earlierClient.Session.MyEphemeralPub!);

        // The old signature covers the old nonces and keys.
        var newClient = NewClientHello();

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(newClient, recorded));
    }

    [Fact]
    public void A8_TagTamper_IsRejectedByAead()
    {
        var (client, server) = Establish();
        SecurePackage package = client.SendChannel!.Encrypt("m1");

        package.Tag[0] ^= 0xFF; // same change as the hub's "TagTamper" mode

        AssertRejected(server.ReceiveChannel!, package, IntegrityFailure);
    }

    [Fact]
    public void A9_CiphertextBitFlip_IsRejectedByAead()
    {
        var (client, server) = Establish();
        SecurePackage package = client.SendChannel!.Encrypt("m1");

        package.Ciphertext[0] ^= 0x01;

        AssertRejected(server.ReceiveChannel!, package, IntegrityFailure);
    }

    [Fact]
    public void A10_SequenceFieldTamper_IsRejectedByAead_BeforeSequenceCheck()
    {
        var (client, server) = Establish();
        SecurePackage package = client.SendChannel!.Encrypt("m1");

        // The "OutOfOrder" mode only rewrites the field. The sequence number is in the AAD,
        // so the tag check rejects the record before the sequence check runs.
        package.SequenceNumber += 2;

        AssertRejected(server.ReceiveChannel!, package, IntegrityFailure);
    }

    [Fact]
    public void A11_GenuineReordering_IsRejectedBySequenceCheck()
    {
        var (client, server) = Establish();
        SecurePackage first = client.SendChannel!.Encrypt("m1");
        SecurePackage second = client.SendChannel!.Encrypt("m2");

        AssertRejected(server.ReceiveChannel!, second, SequenceFailure);
        Assert.Equal("m1", server.ReceiveChannel!.Decrypt(first));
        Assert.Equal("m2", server.ReceiveChannel!.Decrypt(second));
    }

    [Fact]
    public void A12_Replay_IsRejectedBySequenceCheck_WithoutPlaintextExposure()
    {
        var (client, server) = Establish();
        SecurePackage package = client.SendChannel!.Encrypt("tek-seferlik");

        Assert.Equal("tek-seferlik", server.ReceiveChannel!.Decrypt(package));
        Exception ex = AssertRejected(server.ReceiveChannel!, package, SequenceFailure);
        Assert.DoesNotContain("tek-seferlik", ex.Message);
    }

    [Fact]
    public void A13_Suppression_IsDetectedAtNextPacket_AndChannelStaysDesynchronized()
    {
        var (client, server) = Establish();
        _ = client.SendChannel!.Encrypt("m1"); // dropped on the way
        SecurePackage second = client.SendChannel!.Encrypt("m2");
        SecurePackage third = client.SendChannel!.Encrypt("m3");

        AssertRejected(server.ReceiveChannel!, second, SequenceFailure);
        AssertRejected(server.ReceiveChannel!, third, SequenceFailure);
    }

    [Fact]
    public void A14_Reflection_IsRejectedByDirectionSeparatedKeys()
    {
        var (_, server) = Establish();
        SecurePackage fromServer = server.SendChannel!.Encrypt("sunucu-mesaji");

        AssertRejected(server.ReceiveChannel!, fromServer, IntegrityFailure);
    }

    [Fact]
    public void A15_CrossSessionReplay_IsRejectedByAead()
    {
        var (clientA, _) = Establish();
        var (_, serverB) = Establish();
        SecurePackage fromSessionA = clientA.SendChannel!.Encrypt("m1");

        AssertRejected(serverB.ReceiveChannel!, fromSessionA, IntegrityFailure);
    }

    [Fact]
    public void A16_ForgedPacket_WithAttackerKey_IsRejectedByAead()
    {
        var (_, server) = Establish();
        var attackerChannel = new SecureChannel(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(12));
        SecurePackage forged = attackerChannel.Encrypt("sahte");

        AssertRejected(server.ReceiveChannel!, forged, IntegrityFailure);
    }

    private sealed record ClientHello(CryptoProtocolSession Session, byte[] Nonce);

    private static IdentityService ServerIdentity() =>
        IdentityService.CreateFromPrivateSeed(Convert.FromHexString(ProtocolIdentity.DemoServerSeedHex));

    private static ClientHello NewClientHello() => new(
        new CryptoProtocolSession(new IdentityService(ProtocolIdentity.GetPinnedServerPublicKey()), "Client"),
        RandomNumberGenerator.GetBytes(16));

    // Same steps as CryptoHub.BobProcessClientHello: the server signs what it received.
    private static ServerHelloMessage ServerRespond(byte[] receivedClientNonce, byte[] receivedClientEph) =>
        ServerRespond(receivedClientNonce, receivedClientEph, out _);

    private static ServerHelloMessage ServerRespond(byte[] receivedClientNonce, byte[] receivedClientEph,
        out CryptoProtocolSession serverSession)
    {
        IdentityService serverIdentity = ServerIdentity();
        serverSession = new CryptoProtocolSession(serverIdentity, "Server");
        byte[] serverNonce = RandomNumberGenerator.GetBytes(16);

        serverSession.FinalizeHandshake(Array.Empty<byte>(), receivedClientEph, receivedClientNonce, serverNonce);

        return SignHello(serverIdentity, serverIdentity.GetPublicKey(),
            receivedClientNonce, serverNonce, receivedClientEph, serverSession.MyEphemeralPub!);
    }

    private static ServerHelloMessage SignHello(IdentityService signer, byte[] advertisedIdentityKey,
        byte[] clientNonce, byte[] serverNonce, byte[] clientEph, byte[] serverEph)
    {
        byte[] transcript = ProtocolHelpers.BuildHandshakeTranscript(
            clientNonce, serverNonce, clientEph, serverEph, advertisedIdentityKey);

        return new ServerHelloMessage
        {
            SessionId = Guid.NewGuid(),
            ServerNonce = serverNonce,
            ServerEphemeralPublicKey = serverEph,
            ServerIdentityPublicKey = advertisedIdentityKey,
            Signature = signer.SignData(transcript)
        };
    }

    private static ServerHelloVerificationResult ClientVerify(ClientHello client, ServerHelloMessage hello) =>
        ServerHelloVerifier.Verify(
            ProtocolIdentity.GetPinnedServerPublicKey(),
            client.Nonce,
            client.Session.MyEphemeralPub!,
            hello);

    private static (CryptoProtocolSession Client, CryptoProtocolSession Server) Establish()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client.Nonce, client.Session.MyEphemeralPub!, out var server);

        Assert.Equal(ServerHelloVerificationResult.Accepted, ClientVerify(client, hello));
        client.Session.FinalizeHandshake(
            hello.ServerIdentityPublicKey, hello.ServerEphemeralPublicKey, client.Nonce, hello.ServerNonce);

        return (client.Session, server);
    }

    private static Exception AssertRejected(SecureChannel receiver, SecurePackage package, string expectedReason)
    {
        Exception ex = Assert.Throws<Exception>(() => receiver.Decrypt(package));
        Assert.Contains(expectedReason, ex.Message);
        return ex;
    }
}
