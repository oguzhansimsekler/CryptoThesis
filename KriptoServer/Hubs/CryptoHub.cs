namespace KriptoServer.Hubs
{
    using CryptoLibrary;
    using Microsoft.AspNetCore.SignalR;
    using System.Collections.Concurrent;
    using System.Text.Json;

    public class CryptoHub : Hub
    {
        private static readonly IdentityService _bobIdentity = ProtocolIdentity.CreateServerIdentity();
        private static readonly ConcurrentDictionary<Guid, ServerSessionState> _activeSessions = new();

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

        public async Task BobProcessClientHello(string json, bool isTampered)
        {
            var clientHello = JsonSerializer.Deserialize<ClientHelloMessage>(json);
            if (clientHello == null)
            {
                return;
            }

            try
            {
                if (isTampered && clientHello.ClientEphemeralPublicKey.Length > 0)
                {
                    clientHello.ClientEphemeralPublicKey[0] ^= 0xFF;
                }

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

        public async Task ForwardToAlice(string json, bool isTampered)
        {
            if (!isTampered)
            {
                await Clients.Caller.SendAsync("FinalizeServerHello", json);
                return;
            }

            var serverHello = JsonSerializer.Deserialize<ServerHelloMessage>(json);
            if (serverHello == null)
            {
                await Clients.Caller.SendAsync("FinalizeServerHello", json);
                return;
            }

            if (serverHello.Signature.Length > 0)
            {
                serverHello.Signature[0] ^= 0xFF;
            }

            await Clients.Caller.SendAsync("FinalizeServerHello", JsonSerializer.Serialize(serverHello));
        }

        public async Task RelayMessage(Guid sessionId, string messageJson, bool isTampered)
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

            try
            {
                package = JsonSerializer.Deserialize<SecurePackage>(messageJson);
            }
            catch
            {
                package = null;
            }

            if (package == null)
            {
                await Clients.Caller.SendAsync("ReceiveDeliveryReport", new DeliveryReport
                {
                    Success = false,
                    StatusMessage = "Veri paketi okunamadi."
                });
                return;
            }

            if (isTampered)
            {
                TamperPackage(package);
            }

            try
            {
                string plaintext = state.Session.Channel!.Decrypt(package);
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

        private static void TamperPackage(SecurePackage package)
        {
            if (package.Tag?.Length > 0)
            {
                package.Tag[0] ^= 0xFF;
                return;
            }

            if (package.Ciphertext?.Length > 0)
            {
                package.Ciphertext[0] ^= 0xFF;
            }
        }
    }
}
