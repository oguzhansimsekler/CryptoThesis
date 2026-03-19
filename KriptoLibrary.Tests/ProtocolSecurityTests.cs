using CryptoLibrary;
using System.Security.Cryptography;
using Xunit;

namespace KriptoLibrary.Tests;

public class ProtocolSecurityTests
{
    [Fact]
    public void ClientAndServer_DeriveSameSession_AndExchangeMessage()
    {
        var (clientSession, serverSession, clientNonce, serverNonce) = CreateConnectedSessions();

        Assert.NotNull(clientSession.Channel);
        Assert.NotNull(serverSession.Channel);
        Assert.Equal(clientSession.TranscriptHash, serverSession.TranscriptHash);

        SecurePackage package = clientSession.Channel!.Encrypt("tez-protokol-mesaji");
        string plaintext = serverSession.Channel!.Decrypt(package);

        Assert.Equal("tez-protokol-mesaji", plaintext);
    }

    [Fact]
    public void TamperedTag_IsRejectedByServerChannel()
    {
        var (clientSession, serverSession, _, _) = CreateConnectedSessions();
        SecurePackage package = clientSession.Channel!.Encrypt("butunluk-korunmali");

        package.Tag[0] ^= 0xFF;

        Exception ex = Assert.Throws<Exception>(() => serverSession.Channel!.Decrypt(package));
        Assert.Contains("BÜTÜNLÜK HATASI", ex.Message);
    }

    [Fact]
    public void ReplayAttack_IsRejected()
    {
        var (clientSession, serverSession, _, _) = CreateConnectedSessions();
        SecurePackage package = clientSession.Channel!.Encrypt("tek-seferlik");

        string firstRead = serverSession.Channel!.Decrypt(package);
        Exception ex = Assert.Throws<Exception>(() => serverSession.Channel!.Decrypt(package));

        Assert.Equal("tek-seferlik", firstRead);
        Assert.Contains("REPLAY SALDIRISI", ex.Message);
    }

    [Fact]
    public void InvalidPeerPublicKey_IsRejectedDuringHandshake()
    {
        var handshake = new HandshakeService();
        Exception ex = Assert.Throws<Exception>(() => handshake.DeriveSharedSecret(new byte[] { 0x01, 0x02, 0x03 }));

        Assert.Contains("Public Key formatı geçersiz", ex.Message);
    }

    [Fact]
    public void TamperedServerHelloSignature_IsRejectedByClient()
    {
        var serverIdentity = ProtocolIdentity.CreateServerIdentity();
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

    private static (CryptoProtocolSession ClientSession, CryptoProtocolSession ServerSession, byte[] ClientNonce, byte[] ServerNonce)
        CreateConnectedSessions()
    {
        var serverIdentity = ProtocolIdentity.CreateServerIdentity();
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
