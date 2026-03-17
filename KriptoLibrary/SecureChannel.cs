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
            // 1. Temel Kontroller
            if (package == null || package.Ciphertext == null || package.Tag == null || package.Nonce == null)
            {
                throw new Exception("PAKET BOZUK! (Eksik Veri)");
            }

            // 2. AAD Hazırlığı
            byte[] aad = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(aad, package.SequenceNumber);

            byte[] input = new byte[package.Ciphertext.Length + package.Tag.Length];
            Array.Copy(package.Ciphertext, 0, input, 0, package.Ciphertext.Length);
            Array.Copy(package.Tag, 0, input, package.Ciphertext.Length, package.Tag.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(_key), 128, package.Nonce, aad);

            string plaintext = "";

            try
            {
                // 3. Şifre Çözme Denemesi (Kriptografik Kontrol)
                cipher.Init(false, parameters);
                byte[] plaintextBytes = new byte[cipher.GetOutputSize(input.Length)];

                int len = cipher.ProcessBytes(input, 0, input.Length, plaintextBytes, 0);
                len += cipher.DoFinal(plaintextBytes, len); // <-- Tamper burada yakalanır

                plaintext = Encoding.UTF8.GetString(plaintextBytes, 0, len);
            }
            catch (Exception)
            {
                // Eğer buraya düştüyse, veri değiştirilmiştir (Tamper)
                throw new Exception("BÜTÜNLÜK HATASI! (Tag Mismatch - Veri Değiştirilmiş)");
            }

            // 4. Sıra Numarası Kontrolü (Protokol Kontrolü)
            // Şifre başarıyla çözüldü, PEKİ ZAMANI DOĞRU MU?
            if (package.SequenceNumber != _expectedInboundSequence)
            {
                // Şifre doğru olsa bile, sıra yanlış olduğu için REDDETMELİYİZ.
                // Hatanın sonuna parantez içinde çözülen mesajı da ekliyoruz ki
                // "Bakın bu aslında şu eski mesajdı" diye görebilin.
                throw new Exception($"REPLAY SALDIRISI! (Seq: {package.SequenceNumber} Beklenen: {_expectedInboundSequence}) [İçerik: {plaintext}]");
            }

            // Her şey yolundaysa sırayı ilerlet
            _expectedInboundSequence++;

            return plaintext;
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