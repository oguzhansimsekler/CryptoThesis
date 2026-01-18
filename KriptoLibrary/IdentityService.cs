using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KriptoLibrary
{
    public class IdentityService
    {
        private readonly ECDsa _identityKey;

        public IdentityService()
        {
            // Tez standardı: NIST P-256 Eğrisi
            _identityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        }

        // Public Key'i dışarıya ver (Handshake için)
        public byte[] GetPublicKey() => _identityKey.ExportSubjectPublicKeyInfo();

        // El sıkışma özetini (Transcript) imzala (Authentication)
        public byte[] SignData(byte[] data)
        {
            return _identityKey.SignData(data, HashAlgorithmName.SHA256);
        }

        // Karşı tarafın imzasını doğrula
        public bool VerifySignature(byte[] publicKey, byte[] data, byte[] signature)
        {
            using var validator = ECDsa.Create();
            validator.ImportSubjectPublicKeyInfo(publicKey, out _);
            return validator.VerifyData(data, signature, HashAlgorithmName.SHA256);
        }
    }
}
