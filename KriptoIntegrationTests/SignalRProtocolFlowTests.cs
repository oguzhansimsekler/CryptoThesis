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
        using var httpClient = _factory.CreateClient();
        await using var connection = CreateHubConnection();

        var packetQueue = new ConcurrentQueue<(string Type, string Json, bool IsTampered)>();
        var finalizeServerHello = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var deliveryReport = new TaskCompletionSource<DeliveryReport>(TaskCreationOptions.RunContinuationsAsynchronously);

        connection.On<string, string, bool>("ReceiveHandshakePackage", (type, json, isTampered) =>
        {
            packetQueue.Enqueue((type, json, isTampered));
        });

        connection.On<string>("FinalizeServerHello", json =>
        {
            finalizeServerHello.TrySetResult(json);
        });

        connection.On<DeliveryReport>("ReceiveDeliveryReport", report =>
        {
            deliveryReport.TrySetResult(report);
        });

        await connection.StartAsync();

        var clientSession = new CryptoProtocolSession(new IdentityService(ProtocolIdentity.GetPinnedServerPublicKey()), "Client");
        Guid sessionId = Guid.NewGuid();
        byte[] clientNonce = RandomNumberGenerator.GetBytes(16);

        var clientHello = new ClientHelloMessage
        {
            SessionId = sessionId,
            ClientNonce = clientNonce,
            ClientEphemeralPublicKey = clientSession.MyEphemeralPub!
        };

        await connection.InvokeAsync("PostClientHello", clientHello);
        string clientHelloJson = await WaitForPacketJsonAsync(packetQueue, "ClientHello");
        await connection.InvokeAsync("BobProcessClientHello", clientHelloJson, "None");

        string serverHelloJson = await WaitForPacketJsonAsync(packetQueue, "ServerHello");
        await connection.InvokeAsync("ForwardToAlice", serverHelloJson, "None");

        string finalizedHelloJson = await finalizeServerHello.Task.WaitAsync(TimeSpan.FromSeconds(5));
        ServerHelloMessage? serverHello = JsonSerializer.Deserialize<ServerHelloMessage>(finalizedHelloJson);

        Assert.NotNull(serverHello);
        Assert.Equal(ProtocolIdentity.GetPinnedServerPublicKey(), serverHello!.ServerIdentityPublicKey);

        byte[] transcript = ProtocolHelpers.BuildHandshakeTranscript(
            clientNonce,
            serverHello.ServerNonce,
            clientSession.MyEphemeralPub!,
            serverHello.ServerEphemeralPublicKey,
            serverHello.ServerIdentityPublicKey);

        Assert.True(clientSession.Identity.VerifySignature(transcript, serverHello.Signature));

        clientSession.FinalizeHandshake(
            serverHello.ServerIdentityPublicKey,
            serverHello.ServerEphemeralPublicKey,
            clientNonce,
            serverHello.ServerNonce);

        SecurePackage package = clientSession.Channel!.Encrypt("entegrasyon-test-mesaji");
        await connection.InvokeAsync("RelayMessage", sessionId, JsonSerializer.Serialize(package), "None");

        DeliveryReport report = await deliveryReport.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(report.Success);
        Assert.Equal("entegrasyon-test-mesaji", report.Plaintext);
        Assert.Contains("dogruladi", report.StatusMessage);
    }

    [Fact]
    public async Task Server_RejectsOutOfOrderPacket_WithDeliveryReport()
    {
        using var httpClient = _factory.CreateClient();
        await using var connection = CreateHubConnection();

        var packetQueue = new ConcurrentQueue<(string Type, string Json, bool IsTampered)>();
        var finalizeServerHello = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var deliveryReport = new TaskCompletionSource<DeliveryReport>(TaskCreationOptions.RunContinuationsAsynchronously);

        connection.On<string, string, bool>("ReceiveHandshakePackage", (type, json, isTampered) =>
        {
            packetQueue.Enqueue((type, json, isTampered));
        });

        connection.On<string>("FinalizeServerHello", json =>
        {
            finalizeServerHello.TrySetResult(json);
        });

        connection.On<DeliveryReport>("ReceiveDeliveryReport", report =>
        {
            deliveryReport.TrySetResult(report);
        });

        await connection.StartAsync();

        var clientSession = new CryptoProtocolSession(new IdentityService(ProtocolIdentity.GetPinnedServerPublicKey()), "Client");
        Guid sessionId = Guid.NewGuid();
        byte[] clientNonce = RandomNumberGenerator.GetBytes(16);

        await connection.InvokeAsync("PostClientHello", new ClientHelloMessage
        {
            SessionId = sessionId,
            ClientNonce = clientNonce,
            ClientEphemeralPublicKey = clientSession.MyEphemeralPub!
        });

        string clientHelloJson = await WaitForPacketJsonAsync(packetQueue, "ClientHello");
        await connection.InvokeAsync("BobProcessClientHello", clientHelloJson, "None");

        string serverHelloJson = await WaitForPacketJsonAsync(packetQueue, "ServerHello");
        await connection.InvokeAsync("ForwardToAlice", serverHelloJson, "None");

        string finalizedHelloJson = await finalizeServerHello.Task.WaitAsync(TimeSpan.FromSeconds(5));
        ServerHelloMessage serverHello = JsonSerializer.Deserialize<ServerHelloMessage>(finalizedHelloJson)!;

        clientSession.FinalizeHandshake(
            serverHello.ServerIdentityPublicKey,
            serverHello.ServerEphemeralPublicKey,
            clientNonce,
            serverHello.ServerNonce);

        SecurePackage package = clientSession.Channel!.Encrypt("sira-testi");
        await connection.InvokeAsync("RelayMessage", sessionId, JsonSerializer.Serialize(package), "OutOfOrder");

        DeliveryReport report = await deliveryReport.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(report.Success);
        Assert.Contains("Bob paketi reddetti", report.StatusMessage);
    }

    [Fact]
    public async Task Server_RejectsForgedInjection_WithUnknownSessionId()
    {
        using var httpClient = _factory.CreateClient();
        await using var connection = CreateHubConnection();

        var packetQueue = new ConcurrentQueue<(string Type, string Json, bool IsTampered)>();
        var finalizeServerHello = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var deliveryReport = new TaskCompletionSource<DeliveryReport>(TaskCreationOptions.RunContinuationsAsynchronously);

        connection.On<string, string, bool>("ReceiveHandshakePackage", (type, json, isTampered) =>
        {
            packetQueue.Enqueue((type, json, isTampered));
        });

        connection.On<string>("FinalizeServerHello", json =>
        {
            finalizeServerHello.TrySetResult(json);
        });

        connection.On<DeliveryReport>("ReceiveDeliveryReport", report =>
        {
            deliveryReport.TrySetResult(report);
        });

        await connection.StartAsync();

        var clientSession = new CryptoProtocolSession(new IdentityService(ProtocolIdentity.GetPinnedServerPublicKey()), "Client");
        Guid sessionId = Guid.NewGuid();
        byte[] clientNonce = RandomNumberGenerator.GetBytes(16);

        await connection.InvokeAsync("PostClientHello", new ClientHelloMessage
        {
            SessionId = sessionId,
            ClientNonce = clientNonce,
            ClientEphemeralPublicKey = clientSession.MyEphemeralPub!
        });

        string clientHelloJson = await WaitForPacketJsonAsync(packetQueue, "ClientHello");
        await connection.InvokeAsync("BobProcessClientHello", clientHelloJson, "None");

        string serverHelloJson = await WaitForPacketJsonAsync(packetQueue, "ServerHello");
        await connection.InvokeAsync("ForwardToAlice", serverHelloJson, "None");

        string finalizedHelloJson = await finalizeServerHello.Task.WaitAsync(TimeSpan.FromSeconds(5));
        ServerHelloMessage serverHello = JsonSerializer.Deserialize<ServerHelloMessage>(finalizedHelloJson)!;

        clientSession.FinalizeHandshake(
            serverHello.ServerIdentityPublicKey,
            serverHello.ServerEphemeralPublicKey,
            clientNonce,
            serverHello.ServerNonce);

        SecurePackage package = clientSession.Channel!.Encrypt("sahte-oturum-denemesi");
        await connection.InvokeAsync("RelayMessage", Guid.NewGuid(), JsonSerializer.Serialize(package), "None");

        DeliveryReport report = await deliveryReport.Task.WaitAsync(TimeSpan.FromSeconds(5));

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

    private static async Task<string> WaitForPacketJsonAsync(
        ConcurrentQueue<(string Type, string Json, bool IsTampered)> packetQueue,
        string expectedType)
    {
        DateTime timeoutAt = DateTime.UtcNow.AddSeconds(5);

        while (DateTime.UtcNow < timeoutAt)
        {
            while (packetQueue.TryDequeue(out var packet))
            {
                if (packet.Type == expectedType)
                {
                    return packet.Json;
                }
            }

            await Task.Delay(50);
        }

        throw new TimeoutException($"Expected packet '{expectedType}' was not received.");
    }
}
