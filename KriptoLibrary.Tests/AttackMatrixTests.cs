using CryptoLibrary;
using System.Security.Cryptography;
using Xunit;

namespace KriptoLibrary.Tests;

/// <summary>
/// Each test applies one attack and checks which check rejects the message:
/// the pinned key, the Ed25519 signature, the key exchange, a Finished value,
/// the AEAD tag, or the sequence number.
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
        ServerHelloMessage hello = ServerRespond(client.Nonce, tamperedKey, client.Session.MyKemEncapsulationKey!, out _);

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A2_ClientNonceTamper_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        byte[] tamperedNonce = (byte[])client.Nonce.Clone();
        tamperedNonce[0] ^= 0xFF;

        ServerHelloMessage hello = ServerRespond(tamperedNonce, client.Session.MyEphemeralPub!, client.Session.MyKemEncapsulationKey!, out _);

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A3_ServerEphemeralKeySubstitution_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client);

        hello.ServerEphemeralPublicKey = new HandshakeService().GetPublicKey(); // attacker's key

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A4_ServerNonceTamper_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client);

        hello.ServerNonce[0] ^= 0xFF;

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A5_SignatureTamper_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client);

        hello.Signature[0] ^= 0xFF; // same change as the hub's "SignatureTamper" mode

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A6_ServerIdentityKeyTamper_IsRejectedByPinnedKeyCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client);

        hello.ServerIdentityPublicKey[0] ^= 0xFF; // same change as the hub's "PinnedKeyMismatch" mode

        Assert.Equal(ServerHelloVerificationResult.PinnedKeyMismatch, ClientVerify(client, hello));
    }

    [Fact]
    public void A7_ServerImpersonation_WithAttackerSigningKey_IsRejected()
    {
        var client = NewClientHello();
        var attackerIdentity = IdentityService.GenerateLongTermIdentity();

        // The attacker sends its own identity key and signs the transcript with it.
        ServerHelloMessage ownIdentity = AttackerRespond(client, attackerIdentity, attackerIdentity.GetPublicKey());
        Assert.Equal(ServerHelloVerificationResult.PinnedKeyMismatch, ClientVerify(client, ownIdentity));

        // The attacker claims the pinned key but signs with its own key.
        ServerHelloMessage claimedIdentity = AttackerRespond(client, attackerIdentity, ProtocolIdentity.GetPinnedServerPublicKey());
        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, claimedIdentity));
    }

    [Theory]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000")] // u = 0
    [InlineData("0100000000000000000000000000000000000000000000000000000000000000")] // u = 1
    [InlineData("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")] // order 8
    public void A18_LowOrderClientKey_IsRejectedByServerKeyAgreement(string lowOrderPointHex)
    {
        // A low-order point would force an all-zero shared secret (RFC 7748, section 6.1).
        var server = new HandshakeService();

        Exception ex = Assert.Throws<Exception>(() => server.DeriveSharedSecret(Convert.FromHexString(lowOrderPointHex)));
        Assert.Contains("Public Key formati gecersiz", ex.Message);
    }

    [Fact]
    public void A17_ServerHelloReplayedFromEarlierSession_IsRejectedByClientSignatureCheck()
    {
        var earlierClient = NewClientHello();
        ServerHelloMessage recorded = ServerRespond(earlierClient);

        // The old signature covers the old nonces and keys.
        var newClient = NewClientHello();

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(newClient, recorded));
    }

    [Fact]
    public void A19_TwoSessionMitM_ReadsTrafficWithoutSignatureCheck_ButIsRejectedWithIt()
    {
        var client = NewClientHello();
        byte[] pinned = ProtocolIdentity.GetPinnedServerPublicKey();

        // Session 1: the attacker acts as a client towards the real server and completes the handshake.
        var attackerAsClient = new CryptoProtocolSession(new IdentityService(pinned), "Client");
        byte[] attackerNonce = RandomNumberGenerator.GetBytes(16);
        ServerHelloMessage fromServer = ServerRespond(attackerNonce, attackerAsClient.MyEphemeralPub!,
            attackerAsClient.MyKemEncapsulationKey!, out var server);
        Assert.Equal(ServerHelloVerificationResult.Accepted,
            ServerHelloVerifier.Complete(attackerAsClient, pinned, attackerNonce, fromServer));
        Assert.True(server.VerifyClientFinished(attackerAsClient.CreateClientFinished()));

        // Session 2: the attacker acts as the server towards the client. It knows the keys of this
        // half, so it can compute a valid ServerFinished; it can only reuse the server's signature.
        var attackerEph = new HandshakeService();
        byte[] attackerServerNonce = RandomNumberGenerator.GetBytes(16);
        var (kemCiphertext, kemSecret) = KemService.Encapsulate(client.Session.MyKemEncapsulationKey!);
        byte[] transcriptHash = ProtocolHelpers.CalculateCanonicalTranscriptHash(
            ProtocolHelpers.GetAnonymousIdentityPlaceholder(), pinned, client.Session.MyEphemeralPub!,
            attackerEph.GetPublicKey(), client.Session.MyKemEncapsulationKey!, kemCiphertext, client.Nonce, attackerServerNonce);
        var keys = KeySchedule.DeriveSessionKeys(
            Concat(attackerEph.DeriveSharedSecret(client.Session.MyEphemeralPub!), kemSecret), transcriptHash);
        var forged = new ServerHelloMessage
        {
            ServerNonce = attackerServerNonce,
            ServerEphemeralPublicKey = attackerEph.GetPublicKey(),
            KemCiphertext = kemCiphertext,
            ServerIdentityPublicKey = pinned,
            Signature = fromServer.Signature,
            ServerFinished = ProtocolHelpers.ComputeServerFinished(keys.ServerFinishedKey, transcriptHash, fromServer.Signature)
        };

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, forged));

        // Without the signature check, the key exchange and even the Finished check succeed.
        client.Session.FinalizeAsClient(pinned, forged.ServerEphemeralPublicKey, kemCiphertext, client.Nonce, attackerServerNonce);
        Assert.True(client.Session.VerifyServerFinished(forged.Signature, forged.ServerFinished));

        var attackerReads = new SecureChannel(keys.ClientToServerKey, keys.ClientToServerNonce);
        SecurePackage fromClient = client.Session.SendChannel!.Encrypt("gizli");
        Assert.Equal("gizli", attackerReads.Decrypt(fromClient));
        Assert.Equal("gizli", server.ReceiveChannel!.Decrypt(attackerAsClient.SendChannel!.Encrypt("gizli")));
    }

    [Fact]
    public void A20_KemCiphertextTamper_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client);

        hello.KemCiphertext[0] ^= 0xFF;

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A21_ClientKemKeyReplacedByAttackerKey_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        var attackerKem = new KemService();

        // The server encapsulates to the attacker, who could then decapsulate the post-quantum secret.
        ServerHelloMessage hello = ServerRespond(client.Nonce, client.Session.MyEphemeralPub!, attackerKem.EncapsulationKey, out _);

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A22_ServerFinishedTamper_IsRejectedByClientFinishedCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client);

        hello.ServerFinished[0] ^= 0xFF; // same change as the hub's "FinishedTamper" mode

        Assert.Equal(ServerHelloVerificationResult.Accepted, ClientVerify(client, hello));
        Assert.Equal(ServerHelloVerificationResult.InvalidServerFinished, ClientComplete(client, hello));
        Assert.False(client.Session.IsConfirmed);
    }

    [Fact]
    public void A23_ClientFinishedTamper_IsRejectedByServerFinishedCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client.Nonce, client.Session.MyEphemeralPub!,
            client.Session.MyKemEncapsulationKey!, out var server);
        Assert.Equal(ServerHelloVerificationResult.Accepted, ClientComplete(client, hello));

        byte[] clientFinished = client.Session.CreateClientFinished();
        clientFinished[0] ^= 0xFF; // same change as the hub's "FinishedTamper" mode

        Assert.False(server.VerifyClientFinished(clientFinished));
        Assert.False(server.IsConfirmed);
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

    private static ServerHelloMessage ServerRespond(ClientHello client) =>
        ServerRespond(client.Nonce, client.Session.MyEphemeralPub!, client.Session.MyKemEncapsulationKey!, out _);

    // Same steps as CryptoHub.BobProcessClientHello: the server signs what it received.
    private static ServerHelloMessage ServerRespond(byte[] receivedNonce, byte[] receivedEph, byte[] receivedKemKey,
        out CryptoProtocolSession serverSession)
    {
        IdentityService serverIdentity = ServerIdentity();
        serverSession = new CryptoProtocolSession(serverIdentity, "Server");
        return Respond(serverSession, serverIdentity, serverIdentity.GetPublicKey(), receivedNonce, receivedEph, receivedKemKey);
    }

    private static ServerHelloMessage AttackerRespond(ClientHello client, IdentityService attackerIdentity, byte[] advertisedIdentityKey) =>
        Respond(new CryptoProtocolSession(attackerIdentity, "Server"), attackerIdentity, advertisedIdentityKey,
            client.Nonce, client.Session.MyEphemeralPub!, client.Session.MyKemEncapsulationKey!);

    private static ServerHelloMessage Respond(CryptoProtocolSession session, IdentityService signer, byte[] advertisedIdentityKey,
        byte[] clientNonce, byte[] clientEph, byte[] clientKemKey)
    {
        byte[] serverNonce = RandomNumberGenerator.GetBytes(16);
        byte[] kemCiphertext = session.FinalizeAsServer(clientEph, clientKemKey, clientNonce, serverNonce);
        byte[] transcript = ProtocolHelpers.BuildHandshakeTranscript(
            clientNonce, serverNonce, clientEph, session.MyEphemeralPub!, clientKemKey, kemCiphertext, advertisedIdentityKey);
        byte[] signature = signer.SignData(transcript);

        return new ServerHelloMessage
        {
            SessionId = Guid.NewGuid(),
            ServerNonce = serverNonce,
            ServerEphemeralPublicKey = session.MyEphemeralPub!,
            KemCiphertext = kemCiphertext,
            ServerIdentityPublicKey = advertisedIdentityKey,
            Signature = signature,
            ServerFinished = session.CreateServerFinished(signature)
        };
    }

    private static ServerHelloVerificationResult ClientVerify(ClientHello client, ServerHelloMessage hello) =>
        ServerHelloVerifier.Verify(ProtocolIdentity.GetPinnedServerPublicKey(), client.Nonce,
            client.Session.MyEphemeralPub!, client.Session.MyKemEncapsulationKey!, hello);

    private static ServerHelloVerificationResult ClientComplete(ClientHello client, ServerHelloMessage hello) =>
        ServerHelloVerifier.Complete(client.Session, ProtocolIdentity.GetPinnedServerPublicKey(), client.Nonce, hello);

    private static (CryptoProtocolSession Client, CryptoProtocolSession Server) Establish()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client.Nonce, client.Session.MyEphemeralPub!,
            client.Session.MyKemEncapsulationKey!, out var server);

        Assert.Equal(ServerHelloVerificationResult.Accepted, ClientComplete(client, hello));
        Assert.True(server.VerifyClientFinished(client.Session.CreateClientFinished()));

        return (client.Session, server);
    }

    private static Exception AssertRejected(SecureChannel receiver, SecurePackage package, string expectedReason)
    {
        Exception ex = Assert.Throws<Exception>(() => receiver.Decrypt(package));
        Assert.Contains(expectedReason, ex.Message);
        return ex;
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }
}
