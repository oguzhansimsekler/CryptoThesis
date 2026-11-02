using CryptoLibrary;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.SignalR.Client;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace KriptoIntegrationTests;

public class SignalRProtocolFlowTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public SignalRProtocolFlowTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task EndToEndHandshake_AndEncryptedMessage_Succeeds()
    {
        await using var hub = await HubSession.StartAsync(CreateHubConnection());
        var (client, sessionId) = await hub.HandshakeAsync(clientFinishedAttack: "None");

        Assert.True(client.IsConfirmed);
        Assert.Contains("ClientFinished dogrulandi", await hub.NextHandshakeUpdateAsync("ClientFinished dogrulandi"));

        DeliveryReport report = await hub.RelayAsync(sessionId, client.SendChannel!.EncryptText("entegrasyon-test-mesaji"), "None");

        Assert.True(report.Success);
        Assert.DoesNotContain("entegrasyon-test-mesaji", report.StatusMessage);
        Assert.NotNull(report.EncryptedEcho);
        Assert.Equal("entegrasyon-test-mesaji", client.ReceiveChannel!.DecryptText(report.EncryptedEcho!));
    }

    [Fact]
    public async Task A24_Server_RejectsOutOfOrderPacket_WithDeliveryReport()
    {
        await using var hub = await HubSession.StartAsync(CreateHubConnection());
        var (client, sessionId) = await hub.HandshakeAsync(clientFinishedAttack: "None");
        await hub.NextHandshakeUpdateAsync("ClientFinished dogrulandi");

        DeliveryReport report = await hub.RelayAsync(sessionId, client.SendChannel!.EncryptText("sira-testi"), "OutOfOrder");

        Assert.False(report.Success);
        Assert.Contains("Bob paketi reddetti", report.StatusMessage);
    }

    [Fact]
    public async Task A33_Server_RejectsForgedInjection_WithUnknownSessionId()
    {
        await using var hub = await HubSession.StartAsync(CreateHubConnection());
        var (client, _) = await hub.HandshakeAsync(clientFinishedAttack: "None");
        await hub.NextHandshakeUpdateAsync("ClientFinished dogrulandi");

        DeliveryReport report = await hub.RelayAsync(Guid.NewGuid(), client.SendChannel!.EncryptText("sahte-oturum-denemesi"), "None");

        Assert.False(report.Success);
        Assert.Contains("aktif bir oturum bulamadi", report.StatusMessage);
    }

    [Fact]
    public async Task A20_Server_RejectsRecord_BeforeClientFinished()
    {
        await using var hub = await HubSession.StartAsync(CreateHubConnection());
        var (client, sessionId) = await hub.HandshakeAsync(clientFinishedAttack: null);

        DeliveryReport report = await hub.RelayAsync(sessionId, client.SendChannel!.EncryptText("erken-kayit"), "None");

        Assert.False(report.Success);
        Assert.Contains("henuz onaylanmadi", report.StatusMessage);
    }

    [Fact]
    public async Task A18_Server_ClosesSession_OnTamperedClientFinished()
    {
        await using var hub = await HubSession.StartAsync(CreateHubConnection());
        var (client, sessionId) = await hub.HandshakeAsync(clientFinishedAttack: "FinishedTamper");

        Assert.Contains("ClientFinished hatali", await hub.NextHandshakeUpdateAsync("ClientFinished hatali"));

        DeliveryReport report = await hub.RelayAsync(sessionId, client.SendChannel!.EncryptText("kapali-oturum"), "None");

        Assert.False(report.Success);
        Assert.Contains("aktif bir oturum bulamadi", report.StatusMessage);
    }

    [Fact]
    public async Task A1_SessionIdCollision_FromAnotherConnection_DoesNotReplaceVictimSession()
    {
        await using var victim = await HubSession.StartAsync(CreateHubConnection());
        await using var attacker = await HubSession.StartAsync(CreateHubConnection());
        var (client, sessionId) = await victim.HandshakeAsync(clientFinishedAttack: "None");
        await victim.NextHandshakeUpdateAsync("ClientFinished dogrulandi");

        // The session id is public: every ClientHello is broadcast on the wire.
        var attackerSession = new CryptoProtocolSession(new IdentityService(ProtocolIdentity.GetPinnedServerPublicKey()), "Client");
        var collidingHello = new ClientHelloMessage
        {
            SessionId = sessionId,
            ClientNonce = RandomNumberGenerator.GetBytes(16),
            ClientEphemeralPublicKey = attackerSession.MyEphemeralPub!,
            KemEncapsulationKey = attackerSession.MyKemEncapsulationKey!
        };
        await attacker.InvokeAsync("BobProcessClientHello", JsonSerializer.Serialize(collidingHello), "None");

        DeliveryReport report = await victim.RelayAsync(sessionId, client.SendChannel!.EncryptText("cakisma-sonrasi"), "None");

        Assert.True(report.Success, report.StatusMessage);
        Assert.Equal("cakisma-sonrasi", client.ReceiveChannel!.DecryptText(report.EncryptedEcho!));
        Assert.Contains("zaten kullaniliyor", await attacker.NextHandshakeUpdateAsync("zaten kullaniliyor"));
    }

    [Fact]
    public async Task A21_ForeignClientFinished_DoesNotCloseVictimSession()
    {
        await using var victim = await HubSession.StartAsync(CreateHubConnection());
        await using var attacker = await HubSession.StartAsync(CreateHubConnection());
        var (client, sessionId) = await victim.HandshakeAsync(clientFinishedAttack: "None");
        await victim.NextHandshakeUpdateAsync("ClientFinished dogrulandi");

        var forged = new ClientFinishedMessage { SessionId = sessionId, ClientFinished = RandomNumberGenerator.GetBytes(32) };
        await attacker.InvokeAsync("BobProcessClientFinished", JsonSerializer.Serialize(forged), "None");

        DeliveryReport report = await victim.RelayAsync(sessionId, client.SendChannel!.EncryptText("hala-acik"), "None");

        Assert.True(report.Success, report.StatusMessage);
        Assert.Contains("Gecersiz ClientFinished", await attacker.NextHandshakeUpdateAsync("Gecersiz ClientFinished"));
    }

    [Fact]
    public async Task A34_RecordFromAnotherConnection_IsTreatedAsUnknownSession()
    {
        await using var victim = await HubSession.StartAsync(CreateHubConnection());
        await using var attacker = await HubSession.StartAsync(CreateHubConnection());
        var (client, sessionId) = await victim.HandshakeAsync(clientFinishedAttack: "None");
        await victim.NextHandshakeUpdateAsync("ClientFinished dogrulandi");

        // Even a valid record, captured from the wire, is not accepted from a different connection.
        SecurePackage captured = client.SendChannel!.EncryptText("baska-baglantidan");
        DeliveryReport report = await attacker.RelayAsync(sessionId, captured, "None");

        Assert.False(report.Success);
        Assert.Contains("aktif bir oturum bulamadi", report.StatusMessage);

        DeliveryReport original = await victim.RelayAsync(sessionId, captured, "None");
        Assert.True(original.Success);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{\"SessionId\":\"00000000-0000-0000-0000-000000000001\",\"ClientNonce\":\"%%%\"}")]
    [InlineData("ClientNonce:15")]
    [InlineData("ClientEphemeralPublicKey:31")]
    [InlineData("KemEncapsulationKey:1183")]
    [InlineData("KemEncapsulationKey:null")]
    public async Task A7_MalformedClientHello_IsRejectedWithoutCreatingSession(string variant)
    {
        await using var hub = await HubSession.StartAsync(CreateHubConnection());
        Guid sessionId = Guid.NewGuid();

        await hub.InvokeAsync("BobProcessClientHello", BuildClientHelloVariant(sessionId, variant), "None");

        Assert.Contains("Gecersiz ClientHello", await hub.NextHandshakeUpdateAsync("Gecersiz ClientHello"));
        DeliveryReport report = await hub.RelayAsync(sessionId, DummyPackage(), "None");
        Assert.Contains("aktif bir oturum bulamadi", report.StatusMessage);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("base64")]
    [InlineData("length")]
    public async Task A19_MalformedClientFinished_IsRejected_AndLeavesSessionUnconfirmed(string variant)
    {
        await using var hub = await HubSession.StartAsync(CreateHubConnection());
        var (client, sessionId) = await hub.HandshakeAsync(clientFinishedAttack: null);

        string json = variant switch
        {
            "not json" => "{",
            "base64" => $"{{\"SessionId\":\"{sessionId}\",\"ClientFinished\":\"@@@@\"}}",
            _ => JsonSerializer.Serialize(new ClientFinishedMessage { SessionId = sessionId, ClientFinished = new byte[31] })
        };
        await hub.InvokeAsync("BobProcessClientFinished", json, "None");

        Assert.Contains("Gecersiz ClientFinished", await hub.NextHandshakeUpdateAsync("Gecersiz ClientFinished"));
        DeliveryReport report = await hub.RelayAsync(sessionId, client.SendChannel!.EncryptText("onaysiz"), "None");
        Assert.Contains("henuz onaylanmadi", report.StatusMessage);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("base64")]
    [InlineData("tag length")]
    [InlineData("empty ciphertext")]
    [InlineData("sequence zero")]
    public async Task A25_MalformedRecord_IsRejected_AndDoesNotDisturbTheChannel(string variant)
    {
        await using var hub = await HubSession.StartAsync(CreateHubConnection());
        var (client, sessionId) = await hub.HandshakeAsync(clientFinishedAttack: "None");
        await hub.NextHandshakeUpdateAsync("ClientFinished dogrulandi");

        SecurePackage valid = client.SendChannel!.EncryptText("gecerli");
        string json = variant switch
        {
            "not json" => "[",
            "base64" => JsonSerializer.Serialize(valid).Replace(Convert.ToBase64String(valid.Tag), "!!"),
            "tag length" => JsonSerializer.Serialize(Modified(valid, p => p.Tag = p.Tag[..15])),
            "empty ciphertext" => JsonSerializer.Serialize(Modified(valid, p => p.Ciphertext = Array.Empty<byte>())),
            _ => JsonSerializer.Serialize(Modified(valid, p => p.SequenceNumber = 0))
        };

        DeliveryReport rejected = await hub.RelayRawAsync(sessionId, json);
        Assert.False(rejected.Success);
        Assert.Contains("okunamadi", rejected.StatusMessage);

        // The malformed copy did not consume a sequence number: the original still goes through.
        DeliveryReport accepted = await hub.RelayAsync(sessionId, valid, "None");
        Assert.True(accepted.Success, accepted.StatusMessage);
    }

    private static string BuildClientHelloVariant(Guid sessionId, string variant)
    {
        if (!variant.Contains(':') || variant.StartsWith("{"))
            return variant;

        var session = new CryptoProtocolSession(new IdentityService(ProtocolIdentity.GetPinnedServerPublicKey()), "Client");
        var hello = new ClientHelloMessage
        {
            SessionId = sessionId,
            ClientNonce = RandomNumberGenerator.GetBytes(16),
            ClientEphemeralPublicKey = session.MyEphemeralPub!,
            KemEncapsulationKey = session.MyKemEncapsulationKey!
        };

        string[] parts = variant.Split(':');
        byte[]? value = parts[1] == "null" ? null : new byte[int.Parse(parts[1])];
        switch (parts[0])
        {
            case "ClientNonce": hello.ClientNonce = value!; break;
            case "ClientEphemeralPublicKey": hello.ClientEphemeralPublicKey = value!; break;
            case "KemEncapsulationKey": hello.KemEncapsulationKey = value!; break;
        }
        return JsonSerializer.Serialize(hello);
    }

    private static SecurePackage Modified(SecurePackage original, Action<SecurePackage> change)
    {
        var copy = new SecurePackage
        {
            SequenceNumber = original.SequenceNumber,
            Ciphertext = (byte[])original.Ciphertext.Clone(),
            Tag = (byte[])original.Tag.Clone()
        };
        change(copy);
        return copy;
    }

    private static SecurePackage DummyPackage() => new()
    {
        SequenceNumber = 1,
        Ciphertext = new byte[1],
        Tag = new byte[16]
    };

    private HubConnection CreateHubConnection()
    {
        return new HubConnectionBuilder()
            .WithUrl(new Uri(_factory.Server.BaseAddress, "/cryptohub"), options =>
            {
                options.Transports = HttpTransportType.LongPolling;
                options.HttpMessageHandlerFactory = _ => _factory.Server.CreateHandler();
            })
            .Build();
    }

    /// <summary>Drives the hub the way the client page does, with the attacker panel forwarding every message.</summary>
    private sealed class HubSession : IAsyncDisposable
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private readonly HubConnection _connection;
        private readonly ConcurrentQueue<(string Type, string Json)> _packets = new();
        private readonly ConcurrentQueue<string> _finalizedServerHellos = new();
        private readonly ConcurrentQueue<string> _handshakeUpdates = new();
        private readonly ConcurrentQueue<DeliveryReport> _reports = new();

        private HubSession(HubConnection connection)
        {
            _connection = connection;
            connection.On<string, string, bool>("ReceiveHandshakePackage", (type, json, _) => _packets.Enqueue((type, json)));
            connection.On<string>("FinalizeServerHello", json => _finalizedServerHellos.Enqueue(json));
            connection.On<string, string>("UpdateHandshakeUI", (_, message) => _handshakeUpdates.Enqueue(message));
            connection.On<DeliveryReport>("ReceiveDeliveryReport", report => _reports.Enqueue(report));
        }

        public static async Task<HubSession> StartAsync(HubConnection connection)
        {
            var session = new HubSession(connection);
            await connection.StartAsync();
            return session;
        }

        /// <summary>Runs ClientHello and ServerHello; sends ClientFinished unless clientFinishedAttack is null.</summary>
        public async Task<(CryptoProtocolSession Client, Guid SessionId)> HandshakeAsync(string? clientFinishedAttack)
        {
            var client = new CryptoProtocolSession(new IdentityService(ProtocolIdentity.GetPinnedServerPublicKey()), "Client");
            Guid sessionId = Guid.NewGuid();
            byte[] clientNonce = RandomNumberGenerator.GetBytes(16);

            await _connection.InvokeAsync("PostClientHello", new ClientHelloMessage
            {
                SessionId = sessionId,
                ClientNonce = clientNonce,
                ClientEphemeralPublicKey = client.MyEphemeralPub!,
                KemEncapsulationKey = client.MyKemEncapsulationKey!
            });

            await _connection.InvokeAsync("BobProcessClientHello", await WaitForPacketAsync("ClientHello"), "None");
            await _connection.InvokeAsync("ForwardToAlice", await WaitForPacketAsync("ServerHello"), "None");

            var serverHello = JsonSerializer.Deserialize<ServerHelloMessage>(await WaitAsync(_finalizedServerHellos))!;
            Assert.Equal(ServerHelloVerificationResult.Accepted,
                ServerHelloVerifier.Complete(client, ProtocolIdentity.GetPinnedServerPublicKey(), clientNonce, serverHello));

            if (clientFinishedAttack != null)
            {
                var finished = new ClientFinishedMessage { SessionId = sessionId, ClientFinished = client.CreateClientFinished() };
                await _connection.InvokeAsync("BobProcessClientFinished", JsonSerializer.Serialize(finished), clientFinishedAttack);
            }

            return (client, sessionId);
        }

        public async Task<string> NextHandshakeUpdateAsync(string containing)
        {
            DateTime timeoutAt = DateTime.UtcNow + Timeout;
            while (DateTime.UtcNow < timeoutAt)
            {
                while (_handshakeUpdates.TryDequeue(out var message))
                    if (message.Contains(containing))
                        return message;
                await Task.Delay(20);
            }
            throw new TimeoutException($"No handshake update containing '{containing}'.");
        }

        public Task InvokeAsync(string method, string json, string attackMode) =>
            _connection.InvokeAsync(method, json, attackMode);

        public Task<DeliveryReport> RelayAsync(Guid sessionId, SecurePackage package, string attackMode) =>
            RelayRawAsync(sessionId, JsonSerializer.Serialize(package), attackMode);

        public async Task<DeliveryReport> RelayRawAsync(Guid sessionId, string json, string attackMode = "None")
        {
            await _connection.InvokeAsync("RelayMessage", sessionId, json, attackMode);
            return await WaitAsync(_reports);
        }

        private async Task<string> WaitForPacketAsync(string expectedType)
        {
            DateTime timeoutAt = DateTime.UtcNow + Timeout;
            while (DateTime.UtcNow < timeoutAt)
            {
                while (_packets.TryDequeue(out var packet))
                    if (packet.Type == expectedType)
                        return packet.Json;
                await Task.Delay(20);
            }
            throw new TimeoutException($"Expected packet '{expectedType}' was not received.");
        }

        private static async Task<T> WaitAsync<T>(ConcurrentQueue<T> queue)
        {
            DateTime timeoutAt = DateTime.UtcNow + Timeout;
            while (DateTime.UtcNow < timeoutAt)
            {
                if (queue.TryDequeue(out var item))
                    return item;
                await Task.Delay(20);
            }
            throw new TimeoutException($"No {typeof(T).Name} received.");
        }

        public ValueTask DisposeAsync() => _connection.DisposeAsync();
    }
}
