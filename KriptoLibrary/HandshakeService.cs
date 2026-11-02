using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using X25519Math = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace CryptoLibrary
{
    /// <summary>
    /// Ephemeral X25519 key pair. The private scalar is kept in a pinned array owned by this class,
    /// so that Dispose can overwrite it; the garbage collector never moves or copies it.
    /// </summary>
    public sealed class HandshakeService : IDisposable
    {
        private const int X25519KeySize = 32;
        private readonly byte[] _privateKey = GC.AllocateArray<byte>(X25519KeySize, pinned: true);
        private readonly byte[] _publicKey = new byte[X25519KeySize];
        private bool _disposed;

        public HandshakeService()
        {
            X25519Math.GeneratePrivateKey(new SecureRandom(), _privateKey);
            X25519Math.GeneratePublicKey(_privateKey, 0, _publicKey, 0);
        }

        public byte[] GetPublicKey() => (byte[])_publicKey.Clone();

        public byte[] DeriveSharedSecret(byte[] otherPublicKeyBytes)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(HandshakeService));
            if (otherPublicKeyBytes == null || otherPublicKeyBytes.Length != X25519KeySize)
                throw new Exception("HANDSHAKE HATASI: Public Key formati gecersiz.");

            byte[] secret = new byte[X25519KeySize];
            // Returns false for an all-zero result, i.e. a point of small order (RFC 7748, 6.1).
            if (!X25519Math.CalculateAgreement(_privateKey, 0, otherPublicKeyBytes, 0, secret, 0))
                throw new Exception("HANDSHAKE HATASI: Public Key formati gecersiz.");
            return secret;
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(_privateKey);
            _disposed = true;
        }
    }
}
