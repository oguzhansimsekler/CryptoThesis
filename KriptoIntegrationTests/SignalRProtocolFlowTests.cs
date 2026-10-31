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

        DeliveryReport report = await hub.RelayAsync(sessionId, client.SendChannel!.Encrypt("entegrasyon-test-mesaji"), "None");

        Assert.True(report.Success);
        Assert.DoesNotContain("entegrasyon-test-mesaji", report.StatusMessage);
        Assert.NotNull(report.EncryptedEcho);
        Assert.Equal("entegrasyon-test-mesaji", client.ReceiveChannel!.Decrypt(report.EncryptedEcho!));
    }

    [Fact]
    public async Task Server_RejectsOutOfOrderPacket_WithDeliveryReport()
    {
        await using var hub = await HubSession.StartAsync(CreateHubConnection());
        var (client, sessionId) = await hub.HandshakeAsync(clientFinishedAttack: "None");
        await hub.NextHandshakeUpdateAsync("ClientFinished dogrulandi");

        DeliveryReport report = await hub.RelayAsync(sessionId, client.SendChannel!.Encrypt("sira-testi"), "OutOfOrder");

        Assert.False(report.Success);
        Assert.Contains("Bob paketi reddetti", report.StatusMessage);
    }

    [Fact]
    public async Task Server_RejectsForgedInjection_WithUnknownSessionId()
    {
        await using var hub = await HubSession.StartAsync(CreateHubConnection());
        var (client, _) = await hub.HandshakeAsync(clientFinishedAttack: "None");
        await hub.NextHandshakeUpdateAsync("ClientFinished dogrulandi");

        DeliveryReport report = await hub.RelayAsync(Guid.NewGuid(), client.SendChannel!.Encrypt("sahte-oturum-denemesi"), "None");

        Assert.False(report.Success);
        Assert.Contains("aktif bir oturum bulamadi", report.StatusMessage);
    }

    [Fact]
    public async Task Server_RejectsRecord_BeforeClientFinished()
    {
        await using var hub = await HubSession.StartAsync(CreateHubConnection());
        var (client, sessionId) = await hub.HandshakeAsync(clientFinishedAttack: null);

        DeliveryReport report = await hub.RelayAsync(sessionId, client.SendChannel!.Encrypt("erken-kayit"), "None");

        Assert.False(report.Success);
        Assert.Contains("henuz onaylanmadi", report.StatusMessage);
    }

    [Fact]
    public async Task Server_ClosesSession_OnTamperedClientFinished()
    {
        await using var hub = await HubSession.StartAsync(CreateHubConnection());
        var (client, sessionId) = await hub.HandshakeAsync(clientFinishedAttack: "FinishedTamper");

        Assert.Contains("ClientFinished hatali", await hub.NextHandshakeUpdateAsync("ClientFinished hatali"));

        DeliveryReport report = await hub.RelayAsync(sessionId, client.SendChannel!.Encrypt("kapali-oturum"), "None");

        Assert.False(report.Success);
        Assert.Contains("aktif bir oturum bulamadi", report.StatusMessage);
    }

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

        public async Task<DeliveryReport> RelayAsync(Guid sessionId, SecurePackage package, string attackMode)
        {
            await _connection.InvokeAsync("RelayMessage", sessionId, JsonSerializer.Serialize(package), attackMode);
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
