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
    public void A3_ClientEphemeralKeyTamper_IsAcceptedByServer_ButRejectedByClientSignatureCheck()
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
    public void A9_ServerEphemeralKeySubstitution_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client);

        hello.ServerEphemeralPublicKey = new HandshakeService().GetPublicKey(); // attacker's key

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A8_ServerNonceTamper_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client);

        hello.ServerNonce[0] ^= 0xFF;

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A13_SignatureTamper_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client);

        hello.Signature[0] ^= 0xFF; // same change as the hub's "SignatureTamper" mode

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A11_ServerIdentityKeyTamper_IsRejectedByPinnedKeyCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client);

        hello.ServerIdentityPublicKey[0] ^= 0xFF; // same change as the hub's "PinnedKeyMismatch" mode

        Assert.Equal(ServerHelloVerificationResult.PinnedKeyMismatch, ClientVerify(client, hello));
    }

    [Fact]
    public void A12_ServerImpersonation_WithAttackerSigningKey_IsRejected()
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
    public void A4_LowOrderClientKey_IsRejectedByServerKeyAgreement(string lowOrderPointHex)
    {
        // A low-order point would force an all-zero shared secret (RFC 7748, section 6.1).
        var server = new HandshakeService();

        Exception ex = Assert.Throws<Exception>(() => server.DeriveSharedSecret(Convert.FromHexString(lowOrderPointHex)));
        Assert.Contains("Public Key formati gecersiz", ex.Message);
    }

    [Fact]
    public void A16_ServerHelloReplayedFromEarlierSession_IsRejectedByClientSignatureCheck()
    {
        var earlierClient = NewClientHello();
        ServerHelloMessage recorded = ServerRespond(earlierClient);

        // The old signature covers the old nonces and keys.
        var newClient = NewClientHello();

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(newClient, recorded));
    }

    [Fact]
    public void A17_TwoSessionMitM_ReadsTrafficWithoutSignatureCheck_ButIsRejectedWithIt()
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
        SecurePackage fromClient = client.Session.SendChannel!.EncryptText("gizli");
        Assert.Equal("gizli", attackerReads.DecryptText(fromClient));
        Assert.Equal("gizli", server.ReceiveChannel!.DecryptText(attackerAsClient.SendChannel!.EncryptText("gizli")));
    }

    [Fact]
    public void A10_KemCiphertextTamper_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client);

        hello.KemCiphertext[0] ^= 0xFF;

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A5_ClientKemKeyReplacedByAttackerKey_IsRejectedByClientSignatureCheck()
    {
        var client = NewClientHello();
        var attackerKem = new KemService();

        // The server encapsulates to the attacker, who could then decapsulate the post-quantum secret.
        ServerHelloMessage hello = ServerRespond(client.Nonce, client.Session.MyEphemeralPub!, attackerKem.EncapsulationKey, out _);

        Assert.Equal(ServerHelloVerificationResult.InvalidSignature, ClientVerify(client, hello));
    }

    [Fact]
    public void A14_ServerFinishedTamper_IsRejectedByClientFinishedCheck()
    {
        var client = NewClientHello();
        ServerHelloMessage hello = ServerRespond(client);

        hello.ServerFinished[0] ^= 0xFF; // same change as the hub's "FinishedTamper" mode

        Assert.Equal(ServerHelloVerificationResult.Accepted, ClientVerify(client, hello));
        Assert.Equal(ServerHelloVerificationResult.InvalidServerFinished, ClientComplete(client, hello));
        Assert.False(client.Session.IsConfirmed);
    }

    [Fact]
    public void A18_ClientFinishedTamper_IsRejectedByServerFinishedCheck()
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
    public void A23_TagTamper_IsRejectedByAead()
    {
        var (client, server) = Establish();
        SecurePackage package = client.SendChannel!.EncryptText("m1");

        package.Tag[0] ^= 0xFF; // same change as the hub's "TagTamper" mode

        AssertRejected(server.ReceiveChannel!, package, IntegrityFailure);
    }

    [Fact]
    public void A24_CiphertextBitFlip_IsRejectedByAead()
    {
        var (client, server) = Establish();
        SecurePackage package = client.SendChannel!.EncryptText("m1");

        package.Ciphertext[0] ^= 0x01;

        AssertRejected(server.ReceiveChannel!, package, IntegrityFailure);
    }

    [Fact]
    public void A25_SequenceFieldTamper_IsRejectedByAead_BeforeSequenceCheck()
    {
        var (client, server) = Establish();
        SecurePackage package = client.SendChannel!.EncryptText("m1");

        // The "OutOfOrder" mode only rewrites the field. The sequence number is in the AAD,
        // so the tag check rejects the record before the sequence check runs.
        package.SequenceNumber += 2;

        AssertRejected(server.ReceiveChannel!, package, IntegrityFailure);
    }

    [Theory]
    [InlineData(SequenceCheckOrder.AfterAuthentication, IntegrityFailure)]
    [InlineData(SequenceCheckOrder.BeforeAuthentication, SequenceFailure)]
    public void A25_RejectingCheck_DependsOnTheOrderOfChecks(SequenceCheckOrder order, string expectedReason)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonceBase = RandomNumberGenerator.GetBytes(12);
        using var sender = new SecureChannel(key, nonceBase);
        using var receiver = new SecureChannel(key, nonceBase, order);

        SecurePackage package = sender.EncryptText("m1");
        package.SequenceNumber += 2;

        // Same record, same attack: only the implementation decides which check reports it.
        AssertRejected(receiver, package, expectedReason);

        package.SequenceNumber -= 2;
        Assert.Equal("m1", receiver.DecryptText(package));
    }

    [Fact]
    public void A27_GenuineReordering_IsRejectedBySequenceCheck()
    {
        var (client, server) = Establish();
        SecurePackage first = client.SendChannel!.EncryptText("m1");
        SecurePackage second = client.SendChannel!.EncryptText("m2");

        AssertRejected(server.ReceiveChannel!, second, SequenceFailure);
        Assert.Equal("m1", server.ReceiveChannel!.DecryptText(first));
        Assert.Equal("m2", server.ReceiveChannel!.DecryptText(second));
    }

    [Fact]
    public void A28_Replay_IsRejectedBySequenceCheck_WithoutPlaintextExposure()
    {
        var (client, server) = Establish();
        SecurePackage package = client.SendChannel!.EncryptText("tek-seferlik");

        Assert.Equal("tek-seferlik", server.ReceiveChannel!.DecryptText(package));
        Exception ex = AssertRejected(server.ReceiveChannel!, package, SequenceFailure);
        Assert.DoesNotContain("tek-seferlik", ex.Message);
    }

    [Fact]
    public void A29_Suppression_IsDetectedAtNextPacket_AndChannelStaysDesynchronized()
    {
        var (client, server) = Establish();
        _ = client.SendChannel!.EncryptText("m1"); // dropped on the way
        SecurePackage second = client.SendChannel!.EncryptText("m2");
        SecurePackage third = client.SendChannel!.EncryptText("m3");

        AssertRejected(server.ReceiveChannel!, second, SequenceFailure);
        AssertRejected(server.ReceiveChannel!, third, SequenceFailure);
    }

    [Fact]
    public void A31_Reflection_IsRejectedByDirectionSeparatedKeys()
    {
        var (_, server) = Establish();
        SecurePackage fromServer = server.SendChannel!.EncryptText("sunucu-mesaji");

        AssertRejected(server.ReceiveChannel!, fromServer, IntegrityFailure);
    }

    [Fact]
    public void A32_CrossSessionReplay_IsRejectedByAead()
    {
        var (clientA, _) = Establish();
        var (_, serverB) = Establish();
        SecurePackage fromSessionA = clientA.SendChannel!.EncryptText("m1");

        AssertRejected(serverB.ReceiveChannel!, fromSessionA, IntegrityFailure);
    }

    [Fact]
    public void A33_ForgedPacket_WithAttackerKey_IsRejectedByAead()
    {
        var (_, server) = Establish();
        var attackerChannel = new SecureChannel(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(12));
        SecurePackage forged = attackerChannel.EncryptText("sahte");

        AssertRejected(server.ReceiveChannel!, forged, IntegrityFailure);
    }

    [Theory]
    [InlineData(nameof(ServerHelloMessage.ServerNonce), ServerHelloVerificationResult.InvalidSignature)]
    [InlineData(nameof(ServerHelloMessage.ServerEphemeralPublicKey), ServerHelloVerificationResult.InvalidSignature)]
    [InlineData(nameof(ServerHelloMessage.KemCiphertext), ServerHelloVerificationResult.InvalidSignature)]
    [InlineData(nameof(ServerHelloMessage.ServerIdentityPublicKey), ServerHelloVerificationResult.PinnedKeyMismatch)]
    [InlineData(nameof(ServerHelloMessage.Signature), ServerHelloVerificationResult.InvalidSignature)]
    [InlineData(nameof(ServerHelloMessage.ServerFinished), ServerHelloVerificationResult.InvalidServerFinished)]
    public void A15_ServerHelloFieldOfWrongLength_IsRejectedByTheCheckThatCoversIt(string field, ServerHelloVerificationResult expected)
    {
        var property = typeof(ServerHelloMessage).GetProperty(field)!;

        foreach (int delta in new[] { -1, 1 })
        {
            var client = NewClientHello();
            ServerHelloMessage hello = ServerRespond(client);
            byte[] original = (byte[])property.GetValue(hello)!;
            // One byte shorter, or one random byte longer. The transcript encodes every length,
            // so a length change is a transcript change.
            byte[] changed = delta < 0 ? original[..^1] : Concat(original, RandomNumberGenerator.GetBytes(1));
            property.SetValue(hello, changed);

            Assert.Equal(expected, ClientComplete(client, hello));
            Assert.False(client.Session.IsConfirmed);
        }
    }

    private sealed record ClientHello(CryptoProtocolSession Session, byte[] Nonce);

    [Fact]
    public void A6_KemKeyWithUnreducedCoefficient_IsRejectedByServerModulusCheck()
    {
        var client = NewClientHello();
        byte[] badKey = (byte[])client.Session.MyKemEncapsulationKey!.Clone();
        // The first 12-bit coefficient becomes 0xFFF, which is not below q = 3329 (FIPS 203, 7.2).
        badKey[0] = 0xFF;
        badKey[1] |= 0x0F;

        Exception ex = Assert.Throws<Exception>(() =>
            ServerRespond(client.Nonce, client.Session.MyEphemeralPub!, badKey, out _));
        Assert.Contains("KEM anahtari gecersiz", ex.Message);

        // Control: the largest reduced value, q - 1 = 3328 = 0xD00, is accepted.
        byte[] boundaryKey = (byte[])client.Session.MyKemEncapsulationKey!.Clone();
        boundaryKey[0] = 0x00;
        boundaryKey[1] = (byte)((boundaryKey[1] & 0xF0) | 0x0D);
        ServerRespond(client.Nonce, client.Session.MyEphemeralPub!, boundaryKey, out _);
    }

    [Fact]
    public void A30_TruncationOfFinalRecords_IsNotDetected()
    {
        var (client, server) = Establish();
        SecurePackage first = client.SendChannel!.EncryptText("1");
        SecurePackage second = client.SendChannel!.EncryptText("2");
        _ = client.SendChannel!.EncryptText("3"); // dropped by the attacker, and nothing follows it

        Assert.Equal("1", server.ReceiveChannel!.DecryptText(first));
        Assert.Equal("2", server.ReceiveChannel!.DecryptText(second));
        // The receiver cannot tell a dropped last record from a sender that stopped:
        // there is no closing message, so the loss surfaces only if another record arrives.
    }

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
        Exception ex = Assert.Throws<Exception>(() => receiver.DecryptText(package));
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
