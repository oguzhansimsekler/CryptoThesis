namespace KriptoServer.Hubs
{
    using Microsoft.AspNetCore.SignalR;
    using CryptoLibrary;
    using KriptoLibrary;
    using System.Collections.Concurrent;
    using System.Text.Json;

    public class CryptoHub : Hub
    {
        private static readonly IdentityService _bobIdentity = new IdentityService(IdentityService.GenerateLongTermKeyPair());
        private static readonly ConcurrentDictionary<Guid, ServerSessionState> _activeSessions = new();

        public class ServerSessionState
        {
            public HandshakeService Handshake { get; set; } = null!;
            public byte[] ServerNonce { get; set; } = null!;
        }

        public async Task<byte[]> GetServerPublicKey() => await Task.FromResult(_bobIdentity.GetPublicKey());

        // Alice'in ilk hamlesi
        public async Task PostClientHello(HandshakeMessage clientHello)
        {
            await Clients.All.SendAsync("ReceiveHandshakePackage", "ClientHello", JsonSerializer.Serialize(clientHello), false);
            await Clients.All.SendAsync("UpdateHandshakeUI", "pending", "Bob: ClientHello bekleniyor...");
        }

        // Bob'un (Server) paket işleme mantığı
        public async Task BobProcessClientHello(string json, bool isTampered)
        {
            var clientHello = JsonSerializer.Deserialize<HandshakeMessage>(json);
            if (clientHello == null) return;

            try
            {
                if (isTampered) { clientHello.EphemeralPublicKey[0] ^= 0xFF; }

                var serverHandshake = new HandshakeService();
                byte[] serverNonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);

                _activeSessions[clientHello.SessionId] = new ServerSessionState
                {
                    Handshake = serverHandshake,
                    ServerNonce = serverNonce
                };

                byte[] transcript = ProtocolHelpers.BuildHandshakeTranscript(
                    clientHello.Nonce, serverNonce, clientHello.EphemeralPublicKey, serverHandshake.GetPublicKey());

                byte[] signature = _bobIdentity.SignData(transcript);

                var serverHello = new HandshakeMessage
                {
                    SessionId = clientHello.SessionId,
                    Nonce = serverNonce,
                    EphemeralPublicKey = serverHandshake.GetPublicKey(),
                    Signature = signature
                };

                // ServerHello'yu ağa (Wire) gönderiyoruz
                await Clients.All.SendAsync("ReceiveHandshakePackage", "ServerHello", JsonSerializer.Serialize(serverHello), false);
                await Clients.All.SendAsync("UpdateHandshakeUI", "success", "Bob: Yanıt hazır ve ağda.");
            }
            catch
            {
                await Clients.All.SendAsync("UpdateHandshakeUI", "error", "❌ BOB: Anahtar doğrulanamadı.");
            }
        }

        // Alice'in tüneli kurmasını sağlayan kritik metot
        public async Task ForwardToAlice(string json)
        {
            await Clients.All.SendAsync("FinalizeServerHello", json);
        }

        public async Task RelayMessage(Guid sessionId, string messageJson, bool isTampered)
        {
            // Bob'un (Server) bu oturumu tanıdığından emin oluyoruz
            if (_activeSessions.TryGetValue(sessionId, out var state))
            {
                // Mesajı tüm ağa (The Wire) gönderiyoruz
                await Clients.All.SendAsync("ReceivePackageJson", messageJson, isTampered);
            }
        }
    }
}