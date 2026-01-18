namespace KriptoServer.Hubs
{
    using Microsoft.AspNetCore.SignalR;
    public class CryptoHub :Hub
    {
        // 1. Handshake Başlatma Sinyali
        public async Task BroadcastHandshakeStep(string step, string message)
        {
            // Tüm bağlı istemcilere (Alice, Bob, İzleyici) durumu bildir
            await Clients.All.SendAsync("UpdateHandshakeUI", step, message);
        }

        // 2. Şifreli Mesaj Gönderimi (Normal Akış)
        public async Task RelayMessage(byte[] encryptedPackage, bool isTampered)
        {
            // "The Wire" (Orta Panel) görsün
            await Clients.All.SendAsync("VisualizePacket", encryptedPackage, isTampered);

            // Bob'a ilet (Simülasyon olduğu için herkese atıyoruz, Bob kendi çözer)
            // Gerçek senaryoda: await Clients.Client(bobConnectionId)...
            await Clients.All.SendAsync("ReceiveMessageAtBob", encryptedPackage);
        }

        // 3. Hacker Saldırısı (Paket Bozma)
        // Client'tan gelen istekle sunucuda paketi bozar ve öyle iletiriz
        public async Task TamperAndRelay(byte[] originalPackage)
        {
            var random = new Random();
            byte[] corrupted = (byte[])originalPackage.Clone();

            // Basit bir bit-flipping saldırısı (ortadan bir byte'ı boz)
            int targetIndex = corrupted.Length / 2;
            corrupted[targetIndex] ^= 0xFF; // Byte'ı ters çevir

            // Bozuk paketi ağa sal
            await RelayMessage(corrupted, isTampered: true);
        }
    }
}
