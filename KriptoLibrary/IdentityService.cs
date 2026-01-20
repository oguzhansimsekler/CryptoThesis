using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Signers;

namespace CryptoLibrary
{
    public class IdentityService
    {
        private readonly AsymmetricCipherKeyPair _keyPair;
        private readonly X9ECParameters _curve;
        private readonly ECDomainParameters _domain;

        public IdentityService()
        {
            // NIST P-256 (secp256r1) Eğrisi
            _curve = ECNamedCurveTable.GetByName("secp256r1");
            _domain = new ECDomainParameters(_curve.Curve, _curve.G, _curve.N, _curve.H);

            // Anahtar Üretimi
            var gen = new ECKeyPairGenerator();
            var secureRandom = new SecureRandom();
            var keyGenParam = new ECKeyGenerationParameters(_domain, secureRandom);
            gen.Init(keyGenParam);
            _keyPair = gen.GenerateKeyPair();
        }

        public byte[] GetPublicKey()
        {
            // Public Key'i byte dizisi olarak dışarı ver (Q noktası - 65 byte uncompressed)
            var pub = (ECPublicKeyParameters)_keyPair.Public;
            return pub.Q.GetEncoded(false);
        }

        public byte[] SignData(byte[] data)
        {
            var signer = new DsaDigestSigner(new ECDsaSigner(), new Sha256Digest());
            signer.Init(true, _keyPair.Private); // İmzalama modu
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        public bool VerifySignature(byte[] publicKeyBytes, byte[] data, byte[] signature)
        {
            try
            {
                // Byte dizisinden Public Key nesnesini geri oluştur
                var q = _curve.Curve.DecodePoint(publicKeyBytes);
                var pubKeyParam = new ECPublicKeyParameters(q, _domain);

                var verifier = new DsaDigestSigner(new ECDsaSigner(), new Sha256Digest());
                verifier.Init(false, pubKeyParam); // Doğrulama modu
                verifier.BlockUpdate(data, 0, data.Length);
                return verifier.VerifySignature(signature);
            }
            catch
            {
                return false;
            }
        }
    }
}