using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CryptoLibrary
{
    public class HandshakeService
    {
        private const int X25519KeySize = 32;
        private readonly X25519PrivateKeyParameters _privateKey;
        private readonly X25519PublicKeyParameters _publicKey;

        public HandshakeService()
        {
            _privateKey = new X25519PrivateKeyParameters(new SecureRandom());
            _publicKey = _privateKey.GeneratePublicKey();
        }

        public byte[] GetPublicKey()
        {
            byte[] output = new byte[X25519KeySize];
            _publicKey.Encode(output, 0);
            return output;
        }

        public byte[] DeriveSharedSecret(byte[] otherPublicKeyBytes)
        {
            if (otherPublicKeyBytes == null || otherPublicKeyBytes.Length != X25519KeySize)
            {
                throw new Exception("HANDSHAKE HATASI: Public Key formati gecersiz.");
            }

            try
            {
                var otherPublicKey = new X25519PublicKeyParameters(otherPublicKeyBytes, 0);
                byte[] secret = new byte[X25519KeySize];
                _privateKey.GenerateSecret(otherPublicKey, secret, 0);
                return secret;
            }
            catch
            {
                throw new Exception("HANDSHAKE HATASI: Public Key formati gecersiz.");
            }
        }
    }
}
