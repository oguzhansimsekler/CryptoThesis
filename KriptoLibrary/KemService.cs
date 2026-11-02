using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CryptoLibrary
{
    /// <summary>
    /// ML-KEM-768 (FIPS 203) for the post-quantum half of the hybrid key exchange.
    /// The client holds a fresh key pair per handshake; the server only encapsulates.
    /// </summary>
    public sealed class KemService : IDisposable
    {
        public const int EncapsulationKeySize = 1184;
        public const int CiphertextSize = 1088;
        public const int SecretSize = 32;

        private static readonly MLKemParameters Parameters = MLKemParameters.ml_kem_768;
        private MLKemPrivateKeyParameters? _decapsulationKey;

        public byte[] EncapsulationKey { get; }

        public KemService()
        {
            var generator = new MLKemKeyPairGenerator();
            generator.Init(new MLKemKeyGenerationParameters(new SecureRandom(), Parameters));
            var keyPair = generator.GenerateKeyPair();
            _decapsulationKey = (MLKemPrivateKeyParameters)keyPair.Private;
            EncapsulationKey = ((MLKemPublicKeyParameters)keyPair.Public).GetEncoded();
        }

        public static (byte[] Ciphertext, byte[] Secret) Encapsulate(byte[] encapsulationKey)
        {
            if (encapsulationKey == null || encapsulationKey.Length != EncapsulationKeySize)
                throw new Exception("HANDSHAKE HATASI: KEM anahtari gecersiz.");

            try
            {
                var publicKey = MLKemPublicKeyParameters.FromEncoding(Parameters, encapsulationKey);
                var encapsulator = new MLKemEncapsulator(Parameters);
                encapsulator.Init(new ParametersWithRandom(publicKey, new SecureRandom()));

                byte[] ciphertext = new byte[encapsulator.EncapsulationLength];
                byte[] secret = new byte[encapsulator.SecretLength];
                encapsulator.Encapsulate(ciphertext, 0, ciphertext.Length, secret, 0, secret.Length);
                return (ciphertext, secret);
            }
            catch
            {
                throw new Exception("HANDSHAKE HATASI: KEM anahtari gecersiz.");
            }
        }

        public byte[] Decapsulate(byte[] ciphertext)
        {
            if (_decapsulationKey == null)
                throw new ObjectDisposedException(nameof(KemService));
            if (ciphertext == null || ciphertext.Length != CiphertextSize)
                throw new Exception("HANDSHAKE HATASI: KEM sifreli metni gecersiz.");

            var decapsulator = new MLKemDecapsulator(Parameters);
            decapsulator.Init(_decapsulationKey);

            byte[] secret = new byte[decapsulator.SecretLength];
            decapsulator.Decapsulate(ciphertext, 0, ciphertext.Length, secret, 0, secret.Length);
            return secret;
        }

        // BouncyCastle keeps the decapsulation key in internal arrays that cannot be overwritten
        // from outside; dropping the reference is the most this class can do.
        public void Dispose() => _decapsulationKey = null;
    }
}
