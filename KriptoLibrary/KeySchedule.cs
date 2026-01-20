using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;

namespace CryptoLibrary
{
    public static class KeySchedule
    {
        /// <summary>
        /// Shared Secret ve Handshake Transcript üzerinden oturum anahtarlarını türetir.
        /// </summary>
        /// <param name="sharedSecret">ECDH çıktısı (32 byte)</param>
        /// <param name="transcriptHash">
        /// GÜVENLİK KRİTİĞİ: Bu hash şu formatta olmalı:
        /// SHA256( "CTPK-HS1" || ClientEphPub || ServerEphPub || ClientIdPub || ServerIdPub )
        /// </param>
        public static (byte[] Key, byte[] NonceBase) DeriveSessionKeys(byte[] sharedSecret, byte[] transcriptHash)
        {
            var hkdf = new HkdfBytesGenerator(new Sha256Digest());

            // Salt olarak Transcript Hash kullanıyoruz (Context Binding)
            byte[] salt = transcriptHash;

            // Info: Protokol versiyonu ve amacı (Domain Separation)
            byte[] info = Encoding.UTF8.GetBytes("CryptoThesis-Protocol-v1-SessionKeys");

            hkdf.Init(new HkdfParameters(sharedSecret, salt, info));

            // Toplam 44 Byte (32 Key + 12 Nonce)
            byte[] keyMaterial = new byte[44];
            hkdf.GenerateBytes(keyMaterial, 0, 44);

            byte[] aesKey = new byte[32];
            byte[] nonceBase = new byte[12];

            Array.Copy(keyMaterial, 0, aesKey, 0, 32);
            Array.Copy(keyMaterial, 32, nonceBase, 0, 12);

            return (aesKey, nonceBase);
        }
    }
}