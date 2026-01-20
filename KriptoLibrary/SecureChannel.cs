using KriptoLibrary;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Buffers.Binary;
using System.Text;

namespace CryptoLibrary
{
    public class SecureChannel
    {
        private readonly byte[] _key;
        private readonly byte[] _nonceBase;
        private ulong _outboundSequence = 0;
        private ulong _expectedInboundSequence = 1; // İlk mesajın Seq numarası 1 olmalı

        public SecureChannel(byte[] key, byte[] nonceBase)
        {
            _key = key;
            _nonceBase = nonceBase;
        }

        public SecurePackage Encrypt(string plaintext)
        {
            _outboundSequence++;

            byte[] nonce = CalculateNonce(_outboundSequence);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

            byte[] aad = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(aad, _outboundSequence);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(_key), 128, nonce, aad);
            cipher.Init(true, parameters);

            byte[] output = new byte[cipher.GetOutputSize(plaintextBytes.Length)];
            int len = cipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, output, 0);
            cipher.DoFinal(output, len);

            // BouncyCastle çıktı ayrıştırma (Ciphertext | Tag)
            int tagSize = 16;
            int ciphertextSize = output.Length - tagSize;

            byte[] ciphertext = new byte[ciphertextSize];
            byte[] tag = new byte[tagSize];

            Array.Copy(output, 0, ciphertext, 0, ciphertextSize);
            Array.Copy(output, ciphertextSize, tag, 0, tagSize);

            return new SecurePackage
            {
                Ciphertext = ciphertext,
                Tag = tag,
                Nonce = nonce,
                SequenceNumber = _outboundSequence
            };
        }

        public string Decrypt(SecurePackage package)
        {
            // --- ESKİ KOD (Çok Sıkı) ---
            /* if (package.SequenceNumber != _expectedInboundSequence)
            {
                throw new Exception($"SIRA HATASI... Beklenen: {_expectedInboundSequence}...");
            }
            */

            // --- YENİ KOD (Demo İçin Esnek) ---
            // Sıra numarası yanlış olsa bile "Warning" verelim ama işlemi DURDURMAYALIM.
            // Böylece kod aşağıya akacak, AES-GCM şifreyi çözmeye çalışacak
            // ve verinin bozuk olduğunu anlayıp asıl istediğimiz "Tag Mismatch" hatasını verecek.

            string warningPrefix = "";
            if (package.SequenceNumber != _expectedInboundSequence)
            {
                // Hatayı fırlatmak yerine değişkene not alıyoruz
                warningPrefix = $"[UYARI: SIRA NO ({package.SequenceNumber}) BEKLENEN ({_expectedInboundSequence}) DEĞİL] ";

                // NOT: Gerçek bir production kodunda burada 'throw' olmalıydı.
                // Ama biz hacker modunda bütünlük hatasını görmek istiyoruz.
            }

            // AAD Hazırlığı (Burada gelen paketin Seq numarası kullanılır)
            byte[] aad = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(aad, package.SequenceNumber);

            byte[] input = new byte[package.Ciphertext.Length + package.Tag.Length];
            Array.Copy(package.Ciphertext, 0, input, 0, package.Ciphertext.Length);
            Array.Copy(package.Tag, 0, input, package.Ciphertext.Length, package.Tag.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(_key), 128, package.Nonce, aad);
            cipher.Init(false, parameters);

            byte[] plaintextBytes = new byte[cipher.GetOutputSize(input.Length)];
            int len = 0;

            try
            {
                // KRİTİK NOKTA BURASI
                // Veri bozulmuşsa (Tamper) veya Seq numarası AAD ile uyuşmazsa burada patlayacak.
                len = cipher.ProcessBytes(input, 0, input.Length, plaintextBytes, 0);
                len += cipher.DoFinal(plaintextBytes, len);
            }
            catch (Exception)
            {
                // İşte kullanıcının görmek istediği hata bu!
                throw new Exception($"{warningPrefix}BÜTÜNLÜK HATASI! (Tag Mismatch - Veri Değiştirilmiş)");
            }

            // Eğer şifre çözüldüyse ama sıra numarası yanlıştıysa sadece sırayı güncelliyoruz
            // (Normalde bu güvensizdir ama demo için kabul edilebilir)
            if (package.SequenceNumber >= _expectedInboundSequence)
            {
                _expectedInboundSequence = package.SequenceNumber + 1;
            }

            string result = Encoding.UTF8.GetString(plaintextBytes, 0, len);

            // Eğer sıra hatası varsa mesajın başına uyarısını ekleyerek döndür
            return warningPrefix + result;
        }
        

        private byte[] CalculateNonce(ulong seq)
        {
            byte[] nonce = (byte[])_nonceBase.Clone();
            byte[] seqBytes = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(seqBytes, seq);

            // İlk 8 byte XOR (TLS-like construction)
            for (int i = 0; i < 8; i++)
            {
                nonce[i] ^= seqBytes[i];
            }
            return nonce;
        }
    }
}