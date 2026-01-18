using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KriptoLibrary
{
    public class KeySchedule
    {
        // Shared Secret -> (AES Key, Nonce Base) dönüşümü
        public static (byte[] Key, byte[] NonceBase) DeriveSessionKeys(
            byte[] sharedSecret,
            byte[] contextInfo) // Transcript Hash buraya gelecek (Context Binding)
        {
            // 1. AES-256 Anahtarı (32 Byte)
            byte[] aesKey = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                sharedSecret,
                32,
                null, // Salt opsiyonel (Simülasyon için null geçtik, geliştirilebilir)
                contextInfo
            );

            // 2. Nonce Base (12 Byte) - Sequence ile XORlanacak kök nonce
            byte[] nonceBase = HKDF.Expand(
                HashAlgorithmName.SHA256,
                aesKey,
                12,
                Encoding.UTF8.GetBytes("nonce_expansion")
            );

            return (aesKey, nonceBase);
        }
    }
}
