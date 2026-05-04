using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;

namespace CryptoLibrary
{
    public static class KeySchedule
    {
        public record SessionKeyMaterial(
            byte[] ClientToServerKey,
            byte[] ClientToServerNonce,
            byte[] ServerToClientKey,
            byte[] ServerToClientNonce);

        // GÜVENLİK KRİTİĞİ: transcriptHash HKDF salt'ı olarak kullanılır (Context Binding).
        // Her yön için bağımsız anahtar + nonce türetilir — kanal asimetrik olur.
        public static SessionKeyMaterial DeriveSessionKeys(byte[] sharedSecret, byte[] transcriptHash)
        {
            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            byte[] info = Encoding.UTF8.GetBytes("CryptoThesis-Protocol-v1-SessionKeys");
            hkdf.Init(new HkdfParameters(sharedSecret, transcriptHash, info));

            // 88 byte: [0..43] Client→Server, [44..87] Server→Client
            byte[] km = new byte[88];
            hkdf.GenerateBytes(km, 0, 88);

            byte[] c2sKey   = new byte[32]; Array.Copy(km,  0, c2sKey,   0, 32);
            byte[] c2sNonce = new byte[12]; Array.Copy(km, 32, c2sNonce, 0, 12);
            byte[] s2cKey   = new byte[32]; Array.Copy(km, 44, s2cKey,   0, 32);
            byte[] s2cNonce = new byte[12]; Array.Copy(km, 76, s2cNonce, 0, 12);

            return new SessionKeyMaterial(c2sKey, c2sNonce, s2cKey, s2cNonce);
        }
    }
}