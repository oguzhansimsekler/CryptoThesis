using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KriptoLibrary
{
    public class HandshakeService : IDisposable
    {
        private readonly ECDiffieHellman _ephemeralKey;

        public HandshakeService()
        {
            // Forward Secrecy için her oturumda yeni bir anahtar (Ephemeral)
            _ephemeralKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        }

        public byte[] GetPublicKey() => _ephemeralKey.ExportSubjectPublicKeyInfo();

        // Karşı tarafın Public Key'ini alıp Ortak Sırrı (Shared Secret) hesaplar
        public byte[] DeriveSharedSecret(byte[] otherPublicKey)
        {
            using var otherKey = ECDiffieHellman.Create();
            otherKey.ImportSubjectPublicKeyInfo(otherPublicKey, out _);
            return _ephemeralKey.DeriveKeyMaterial(otherKey.PublicKey);
        }

        public void Dispose()
        {
            _ephemeralKey?.Dispose();
        }
    }
}
