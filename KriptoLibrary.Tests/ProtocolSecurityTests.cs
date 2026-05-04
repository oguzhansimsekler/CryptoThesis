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

        SecurePackage package = clientSession.SendChannel!.Encrypt("tez-protokol-mesaji");
        string plaintext = serverSession.ReceiveChannel!.Decrypt(package);

        Assert.Equal("tez-protokol-mesaji", plaintext);
    }

    [Fact]
    public void TamperedTag_IsRejectedByServerChannel()
    {
        var (clientSession, serverSession, _, _) = CreateConnectedSessions();
        SecurePackage package = clientSession.SendChannel!.Encrypt("butunluk-korunmali");

        package.Tag[0] ^= 0xFF;

        Exception ex = Assert.Throws<Exception>(() => serverSession.ReceiveChannel!.Decrypt(package));
        Assert.Contains("BÜTÜNLÜK HATASI", ex.Message);
    }

    [Fact]
    public void ReplayAttack_IsRejected()
    {
        var (clientSession, serverSession, _, _) = CreateConnectedSessions();
        const string message = "tek-seferlik";
        SecurePackage package = clientSession.SendChannel!.Encrypt(message);

        string firstRead = serverSession.ReceiveChannel!.Decrypt(package);
        Exception ex = Assert.Throws<Exception>(() => serverSession.ReceiveChannel!.Decrypt(package));

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

        byte[] transcript = ProtocolHelpers.BuildHandshakeTranscript(
            clientNonce,
            serverNonce,
            clientSession.MyEphemeralPub!,
            serverSession.MyEphemeralPub!,
            serverIdentityPublicKey);

        byte[] signature = serverIdentity.SignData(transcript);
        signature[0] ^= 0xFF;

        Assert.False(clientIdentity.VerifySignature(transcript, signature));
    }

    [Fact]
    public void ClientSendChannel_AndServerReceiveChannel_UseOppositeKeys()
    {
        var (clientSession, serverSession, _, _) = CreateConnectedSessions();

        // Server'ın SendChannel → Client'ın ReceiveChannel ile şifre çözülmeli
        SecurePackage fromServer = serverSession.SendChannel!.Encrypt("sunucudan-istemciye");
        string decrypted = clientSession.ReceiveChannel!.Decrypt(fromServer);

        Assert.Equal("sunucudan-istemciye", decrypted);
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

        serverSession.FinalizeHandshake(
            Array.Empty<byte>(),
            clientSession.MyEphemeralPub!,
            clientNonce,
            serverNonce);

        clientSession.FinalizeHandshake(
            serverIdentity.GetPublicKey(),
            serverSession.MyEphemeralPub!,
            clientNonce,
            serverNonce);

        return (clientSession, serverSession, clientNonce, serverNonce);
    }
}
