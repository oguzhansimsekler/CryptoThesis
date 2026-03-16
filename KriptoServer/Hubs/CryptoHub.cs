namespace KriptoServer.Hubs
{
    using Microsoft.AspNetCore.SignalR;
    using CryptoLibrary; // Kripto sınıflarımız için eklendi
    using System;
    using System.Threading.Tasks;

    public class CryptoHub : Hub
    {
        // --- 1. SUNUCU KİMLİĞİ (YENİ EKLENDİ) ---
        // Sunucunun uzun ömürlü (long-term) kimliği.
        // Uygulama çalıştığı sürece aynı Private/Public Key'i kullanması için 'static readonly' yapıyoruz.
        private static readonly IdentityService _serverIdentity = new IdentityService(IdentityService.GenerateLongTermKeyPair());
        // İstemcinin (WASM) sunucuyu doğrulayabilmesi için Public Key'i dışarı açıyoruz.
        // (Gerçek dünyada bu sertifika olarak TLS üzerinden verilir, biz SignalR ile ilk bağlantıda verebiliriz).
        public async Task<byte[]> GetServerPublicKey()
        {
            return _serverIdentity.GetPublicKey();
        }


        // --- 2. GÜVENLİ HANDSHAKE (YENİ EKLENDİ) ---
        // İstemci geçici anahtarını (ClientHello) gönderdiğinde bu metot tetiklenir.
        public async Task StartSecureHandshake(byte[] clientEphemeralPub)
        {
            // Adım 1: Sunucu kendi geçici anahtarını (ECDH) üretir
            var serverHandshake = new HandshakeService();
            byte[] serverEphemeralPub = serverHandshake.GetPublicKey();

            // Adım 2: Transcript oluşturulur (Client Pub + Server Pub)
            byte[] transcript = new byte[clientEphemeralPub.Length + serverEphemeralPub.Length];
            Buffer.BlockCopy(clientEphemeralPub, 0, transcript, 0, clientEphemeralPub.Length);
            Buffer.BlockCopy(serverEphemeralPub, 0, transcript, clientEphemeralPub.Length, serverEphemeralPub.Length);

            // Adım 3: Sunucu, uzun ömürlü kimliği (Private Key) ile transcript'i imzalar (AUTHENTICATION!)
            byte[] signature = _serverIdentity.SignData(transcript);

            // Adım 4: İstemciye (Sadece isteği yapan Client'a) imzalı yanıtı (ServerHello) gönder
            await Clients.Caller.SendAsync("ReceiveServerHello", serverEphemeralPub, signature);

            // Ortadaki "The Wire" (Ağ İzleyicisi) görsün diye UI'a bilgi geçiyoruz
            await Clients.All.SendAsync("UpdateHandshakeUI", "ServerHello", "Sunucu kendi geçici anahtarını ve İMZASINI gönderdi.");
        }


        // --- 3. MEVCUT METOTLARIN (KORUNDU) ---

        // 1. Handshake Başlatma Sinyali
        public async Task BroadcastHandshakeStep(string step, string message)
        {
            await Clients.All.SendAsync("UpdateHandshakeUI", step, message);
        }

        // 2. Şifreli Mesaj İletimi
        public async Task RelayMessage(string messageJson, bool isTampered)
        {
            await Clients.All.SendAsync("ReceivePackageJson", messageJson, isTampered);
        }

        // 3. SALDIRI SİMÜLASYONU (Hacker Modu)
        public async Task TamperAndRelay(string messageJson)
        {
            char[] chars = messageJson.ToCharArray();

            int index = messageJson.Length / 2;
            if (chars[index] == '"' || chars[index] == ':' || chars[index] == ',' || chars[index] == '{' || chars[index] == '}')
            {
                index++;
            }

            chars[index] = (chars[index] == 'A') ? 'B' : 'A';

            string tamperedJson = new string(chars);

            await Clients.All.SendAsync("ReceivePackageJson", tamperedJson, true);
        }
    }
}