namespace KriptoServer.Hubs
{
    using Microsoft.AspNetCore.SignalR;
    public class CryptoHub :Hub
    {
        // 1. Handshake Başlatma Sinyali
        public async Task BroadcastHandshakeStep(string step, string message)
        {
            await Clients.All.SendAsync("UpdateHandshakeUI", step, message);
        }

        // 2. Şifreli Mesaj İletimi (GÜNCELLENMİŞ HALİ)
        // Artık byte[] değil, string (JSON) taşıyoruz.
        public async Task RelayMessage(string messageJson, bool isTampered)
        {
            // 1. "The Wire" (Orta Panel) görsün diye herkese atıyoruz
            // İsim değişikliği: Client tarafında "ReceivePackageJson" dinleniyor.
            await Clients.All.SendAsync("ReceivePackageJson", messageJson, isTampered);
        }        // 3. Hacker Saldırısı (Paket Bozma)
                 // Client'tan gelen istekle sunucuda paketi bozar ve öyle iletiriz
                 // CryptoHub.cs içine ekle:

        // 3. SALDIRI SİMÜLASYONU (Hacker Modu)
        public async Task TamperAndRelay(string messageJson)
        {
            // Gelen JSON string'i manipüle ediyoruz (Man-in-the-Middle Attack)
            // Amacımız: Veriyi değiştirmek ama JSON formatını tamamen kırmamak.
            // Yöntem: String'in ortalarından bir karakteri 'X' ile değiştiriyoruz.

            char[] chars = messageJson.ToCharArray();

            // Ortadaki karakteri bul (Tırnak işaretine denk gelirse yanındakini al)
            int index = messageJson.Length / 2;
            if (chars[index] == '"' || chars[index] == ':' || chars[index] == ',' || chars[index] == '{' || chars[index] == '}')
            {
                index++;
            }

            // Karakteri değiştir (Bit-flip simülasyonu)
            chars[index] = (chars[index] == 'A') ? 'B' : 'A';

            string tamperedJson = new string(chars);

            // Bob'a "Değiştirilmiş" bayrağıyla (isTampered=true) gönder
            // isTampered=true sadece UI'da kırmızı göstermek içindir; kripto bunu kendisi anlamalı!
            await Clients.All.SendAsync("ReceivePackageJson", tamperedJson, true);
        }
    }
}
