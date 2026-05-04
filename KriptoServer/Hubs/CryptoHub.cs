namespace KriptoServer.Hubs
{
    using CryptoLibrary;
    using Microsoft.AspNetCore.SignalR;
    using System.Collections.Concurrent;
    using System.Text.Json;

    public class CryptoHub : Hub
    {
        private readonly IdentityService _bobIdentity;

        // SessionId → oturum durumu
        private static readonly ConcurrentDictionary<Guid, ServerSessionState> _activeSessions = new();
        // ConnectionId → SessionId (bağlantı koptuğunda temizlik için)
        private static readonly ConcurrentDictionary<string, Guid> _connectionSessions = new();

        public CryptoHub(IdentityService bobIdentity)
        {
            _bobIdentity = bobIdentity;
        }

        public override Task OnDisconnectedAsync(Exception? exception)
        {
            if (_connectionSessions.TryRemove(Context.ConnectionId, out var sessionId))
                _activeSessions.TryRemove(sessionId, out _);

            return base.OnDisconnectedAsync(exception);
        }

        public class ServerSessionState
        {
            public required CryptoProtocolSession Session { get; init; }
            public required byte[] ClientNonce { get; init; }
            public required byte[] ServerNonce { get; init; }
        }

        public async Task PostClientHello(ClientHelloMessage clientHello)
        {
            await Clients.All.SendAsync("ReceiveHandshakePackage", "ClientHello", JsonSerializer.Serialize(clientHello), false);
            await Clients.Caller.SendAsync("UpdateHandshakeUI", "pending", "Bob: ClientHello alindi, dogrulama yapiliyor...");
        }

        public async Task BobProcessClientHello(string json, string attackMode)
        {
            ClientHelloMessage? clientHello;

            try { clientHello = JsonSerializer.Deserialize<ClientHelloMessage>(json); }
            catch { clientHello = null; }

            if (clientHello == null || !IsValidClientHello(clientHello))
            {
                await Clients.Caller.SendAsync("UpdateHandshakeUI", "error", "Bob: Gecersiz ClientHello formati.");
                return;
            }

            try
            {
                if (attackMode == "InvalidClientKey")
                    clientHello.ClientEphemeralPublicKey[0] ^= 0xFF;

                var session = new CryptoProtocolSession(_bobIdentity, "Server");
                byte[] serverNonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
                byte[] serverIdentityPublicKey = _bobIdentity.GetPublicKey();
                byte[] serverEphemeralPublicKey = session.MyEphemeralPub!;

                session.FinalizeHandshake(
                    Array.Empty<byte>(),
                    clientHello.ClientEphemeralPublicKey,
                    clientHello.ClientNonce,
                    serverNonce);

                _activeSessions[clientHello.SessionId] = new ServerSessionState
                {
                    Session = session,
                    ClientNonce = clientHello.ClientNonce,
                    ServerNonce = serverNonce
                };

                // Bağlantı koptuğunda bu session'ı temizleyebilmek için mapping sakla
                _connectionSessions[Context.ConnectionId] = clientHello.SessionId;

                byte[] transcript = ProtocolHelpers.BuildHandshakeTranscript(
                    clientHello.ClientNonce,
                    serverNonce,
                    clientHello.ClientEphemeralPublicKey,
                    serverEphemeralPublicKey,
                    serverIdentityPublicKey);

                byte[] signature = _bobIdentity.SignData(transcript);

                var serverHello = new ServerHelloMessage
                {
                    SessionId = clientHello.SessionId,
                    ServerNonce = serverNonce,
                    ServerEphemeralPublicKey = serverEphemeralPublicKey,
                    ServerIdentityPublicKey = serverIdentityPublicKey,
                    Signature = signature
                };

                await Clients.All.SendAsync("ReceiveHandshakePackage", "ServerHello", JsonSerializer.Serialize(serverHello), false);
                await Clients.Caller.SendAsync("UpdateHandshakeUI", "success", "Bob: ServerHello hazir, oturum anahtari turetildi.");
            }
            catch (Exception ex)
            {
                await Clients.Caller.SendAsync("UpdateHandshakeUI", "error", $"Bob: Handshake reddedildi. {ex.Message}");
            }
        }

        public async Task ForwardToAlice(string json, string attackMode)
        {
            if (attackMode == "None")
            {
                await Clients.Caller.SendAsync("FinalizeServerHello", json);
                return;
            }

            ServerHelloMessage? serverHello;
            try { serverHello = JsonSerializer.Deserialize<ServerHelloMessage>(json); }
            catch { serverHello = null; }

            if (serverHello == null)
            {
                await Clients.Caller.SendAsync("FinalizeServerHello", json);
                return;
            }

            if (attackMode == "SignatureTamper" && serverHello.Signature.Length > 0)
                serverHello.Signature[0] ^= 0xFF;
            else if (attackMode == "PinnedKeyMismatch" && serverHello.ServerIdentityPublicKey.Length > 0)
                serverHello.ServerIdentityPublicKey[0] ^= 0xFF;

            await Clients.Caller.SendAsync("FinalizeServerHello", JsonSerializer.Serialize(serverHello));
        }

        public async Task RelayMessage(Guid sessionId, string messageJson, string attackMode)
        {
            if (!_activeSessions.TryGetValue(sessionId, out var state))
            {
                await Clients.Caller.SendAsync("ReceiveDeliveryReport", new DeliveryReport
                {
                    Success = false,
                    StatusMessage = "Sunucu bu sessionId icin aktif bir oturum bulamadi."
                });
                return;
            }

            SecurePackage? package;
            try { package = JsonSerializer.Deserialize<SecurePackage>(messageJson); }
            catch { package = null; }

            if (package == null || !IsValidPackage(package))
            {
                await Clients.Caller.SendAsync("ReceiveDeliveryReport", new DeliveryReport
                {
                    Success = false,
                    StatusMessage = "Veri paketi okunamadi veya formati gecersiz."
                });
                return;
            }

            if (attackMode == "TagTamper")
                TamperPackage(package);
            else if (attackMode == "OutOfOrder")
                package.SequenceNumber += 2;

            try
            {
                // ReceiveChannel: sunucu, Client→Server yönündeki mesajları burada çözer
                string plaintext = state.Session.ReceiveChannel!.Decrypt(package);
                await Clients.Caller.SendAsync("ReceiveDeliveryReport", new DeliveryReport
                {
                    Success = true,
                    Plaintext = plaintext,
                    StatusMessage = $"Bob mesaji dogruladi ve cozumledi: {plaintext}"
                });
            }
            catch (Exception ex)
            {
                await Clients.Caller.SendAsync("ReceiveDeliveryReport", new DeliveryReport
                {
                    Success = false,
                    StatusMessage = $"Bob paketi reddetti: {ex.Message}"
                });
            }
        }

        private static bool IsValidClientHello(ClientHelloMessage msg) =>
            msg.ClientNonce?.Length == 16 &&
            msg.ClientEphemeralPublicKey?.Length == 32;

        private static bool IsValidPackage(SecurePackage pkg) =>
            pkg.Nonce?.Length == 12 &&
            pkg.Ciphertext?.Length > 0 &&
            pkg.Tag?.Length == 16 &&
            pkg.SequenceNumber > 0;

        private static void TamperPackage(SecurePackage package)
        {
            if (package.Tag?.Length > 0)
            {
                package.Tag[0] ^= 0xFF;
                return;
            }

            if (package.Ciphertext?.Length > 0)
                package.Ciphertext[0] ^= 0xFF;
        }
    }
}
