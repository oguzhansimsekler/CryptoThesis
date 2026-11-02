using CryptoLibrary;
using System.Security.Cryptography;
using Xunit;

namespace KriptoLibrary.Tests;

public class ProtocolSecurityTests
{
    [Fact]
    public void ClientAndServer_DeriveSameSession_AndExchangeMessage()
    {
        var (clientSession, serverSession, _, _) = CreateConnectedSessions();

        Assert.NotNull(clientSession.SendChannel);
        Assert.NotNull(serverSession.ReceiveChannel);
        Assert.Equal(clientSession.TranscriptHash, serverSession.TranscriptHash);

        SecurePackage package = clientSession.SendChannel!.EncryptText("tez-protokol-mesaji");
        string plaintext = serverSession.ReceiveChannel!.DecryptText(package);

        Assert.Equal("tez-protokol-mesaji", plaintext);
    }

    [Fact]
    public void TamperedTag_IsRejectedByServerChannel()
    {
        var (clientSession, serverSession, _, _) = CreateConnectedSessions();
        SecurePackage package = clientSession.SendChannel!.EncryptText("butunluk-korunmali");

        package.Tag[0] ^= 0xFF;

        Exception ex = Assert.Throws<Exception>(() => serverSession.ReceiveChannel!.DecryptText(package));
        Assert.Contains("BÜTÜNLÜK HATASI", ex.Message);
    }

    [Fact]
    public void ReplayAttack_IsRejected()
    {
        var (clientSession, serverSession, _, _) = CreateConnectedSessions();
        const string message = "tek-seferlik";
        SecurePackage package = clientSession.SendChannel!.EncryptText(message);

        string firstRead = serverSession.ReceiveChannel!.DecryptText(package);
        Exception ex = Assert.Throws<Exception>(() => serverSession.ReceiveChannel!.DecryptText(package));

        Assert.Equal(message, firstRead);
        Assert.Contains("REPLAY SALDIRISI", ex.Message);
        Assert.DoesNotContain(message, ex.Message);
    }

    [Fact]
    public void InvalidPeerPublicKey_IsRejectedDuringHandshake()
    {
        var handshake = new HandshakeService();
        Exception ex = Assert.Throws<Exception>(() => handshake.DeriveSharedSecret(new byte[] { 0x01, 0x02, 0x03 }));

        Assert.Contains("Public Key formati gecersiz", ex.Message);
    }

    [Fact]
    public void TamperedServerHelloSignature_IsRejectedByClient()
    {
        var serverIdentity = CreateTestServerIdentity();
        var clientIdentity = new IdentityService(ProtocolIdentity.GetPinnedServerPublicKey());
        var clientSession = new CryptoProtocolSession(clientIdentity, "Client");
        var serverSession = new CryptoProtocolSession(serverIdentity, "Server");
        byte[] clientNonce = RandomNumberGenerator.GetBytes(16);
        byte[] serverNonce = RandomNumberGenerator.GetBytes(16);
        byte[] serverIdentityPublicKey = serverIdentity.GetPublicKey();

        byte[] kemCiphertext = serverSession.FinalizeAsServer(
            clientSession.MyEphemeralPub!, clientSession.MyKemEncapsulationKey!, clientNonce, serverNonce);
        byte[] transcript = ProtocolHelpers.BuildHandshakeTranscript(
            clientNonce,
            serverNonce,
            clientSession.MyEphemeralPub!,
            serverSession.MyEphemeralPub!,
            clientSession.MyKemEncapsulationKey!,
            kemCiphertext,
            serverIdentityPublicKey);

        byte[] signature = serverIdentity.SignData(transcript);
        signature[0] ^= 0xFF;

        Assert.False(clientIdentity.VerifySignature(transcript, signature));
    }

    [Fact]
    public void ClientSendChannel_AndServerReceiveChannel_UseOppositeKeys()
    {
        var (clientSession, serverSession, _, _) = CreateConnectedSessions();

        SecurePackage fromServer = serverSession.SendChannel!.EncryptText("sunucudan-istemciye");
        string decrypted = clientSession.ReceiveChannel!.DecryptText(fromServer);

        Assert.Equal("sunucudan-istemciye", decrypted);
    }

    [Fact]
    public void EphemeralKeys_AreDiscardedOnceSessionKeysAreDerived()
    {
        var (clientSession, serverSession, _, _) = CreateConnectedSessions();

        // Forward secrecy needs the ephemeral secrets to be gone, not just unused.
        Assert.Throws<ObjectDisposedException>(() => clientSession.Handshake.DeriveSharedSecret(serverSession.MyEphemeralPub!));
        Assert.Throws<ObjectDisposedException>(() => serverSession.Handshake.DeriveSharedSecret(clientSession.MyEphemeralPub!));
        Assert.Throws<ObjectDisposedException>(() => clientSession.Kem!.Decapsulate(new byte[KemService.CiphertextSize]));
    }

    [Fact]
    public void DisposedSession_CannotEncryptOrDecrypt()
    {
        var (clientSession, serverSession, _, _) = CreateConnectedSessions();
        SecurePackage package = clientSession.SendChannel!.EncryptText("son-mesaj");

        serverSession.Dispose();
        clientSession.Dispose();

        Assert.Throws<ObjectDisposedException>(() => serverSession.ReceiveChannel!.Decrypt(package));
        Assert.Throws<ObjectDisposedException>(() => clientSession.SendChannel!.EncryptText("sonra"));
    }

    private static IdentityService CreateTestServerIdentity() =>
        IdentityService.CreateFromPrivateSeed(Convert.FromHexString(ProtocolIdentity.DemoServerSeedHex));

    private static (CryptoProtocolSession ClientSession, CryptoProtocolSession ServerSession, byte[] ClientNonce, byte[] ServerNonce)
        CreateConnectedSessions()
    {
        var serverIdentity = CreateTestServerIdentity();
        var clientIdentity = new IdentityService(ProtocolIdentity.GetPinnedServerPublicKey());
        var clientSession = new CryptoProtocolSession(clientIdentity, "Client");
        var serverSession = new CryptoProtocolSession(serverIdentity, "Server");
        byte[] clientNonce = RandomNumberGenerator.GetBytes(16);
        byte[] serverNonce = RandomNumberGenerator.GetBytes(16);

        byte[] kemCiphertext = serverSession.FinalizeAsServer(
            clientSession.MyEphemeralPub!, clientSession.MyKemEncapsulationKey!, clientNonce, serverNonce);

        clientSession.FinalizeAsClient(
            serverIdentity.GetPublicKey(),
            serverSession.MyEphemeralPub!,
            kemCiphertext,
            clientNonce,
            serverNonce);

        return (clientSession, serverSession, clientNonce, serverNonce);
    }
}
