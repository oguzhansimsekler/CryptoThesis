namespace CryptoLibrary
{
    using Org.BouncyCastle.Asn1.X9;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Digests;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Crypto.Signers;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Math.EC;
    using Org.BouncyCastle.Security;
    using System;

    /// <summary>
    /// ECDSA tabanli uzun donem kimlik anahtarlarini ve imza dogrulama akislarini yonetir.
    /// </summary>
    public class IdentityService
    {
        private readonly AsymmetricCipherKeyPair? _signingKeyPair;
        private readonly byte[]? _trustedPublicKey;
        private readonly X9ECParameters _curve;
        private readonly ECDomainParameters _domain;

        public bool HasSigningKey => _signingKeyPair != null;

        public IdentityService(AsymmetricCipherKeyPair signingKeyPair)
        {
            _curve = ECNamedCurveTable.GetByName("secp256r1");
            _domain = new ECDomainParameters(_curve.Curve, _curve.G, _curve.N, _curve.H);
            _signingKeyPair = signingKeyPair;
        }

        public IdentityService(byte[] trustedPublicKey)
        {
            _curve = ECNamedCurveTable.GetByName("secp256r1");
            _domain = new ECDomainParameters(_curve.Curve, _curve.G, _curve.N, _curve.H);
            _trustedPublicKey = trustedPublicKey;
        }

        public static AsymmetricCipherKeyPair GenerateLongTermKeyPair()
        {
            var curve = ECNamedCurveTable.GetByName("secp256r1");
            var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var gen = new ECKeyPairGenerator();
            gen.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
            return gen.GenerateKeyPair();
        }

        public static AsymmetricCipherKeyPair CreateLongTermKeyPairFromPrivateScalar(byte[] privateScalarBytes)
        {
            var curve = ECNamedCurveTable.GetByName("secp256r1");
            var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var d = new BigInteger(1, privateScalarBytes);

            if (d.SignValue <= 0 || d.CompareTo(domain.N) >= 0)
            {
                throw new ArgumentException("Private scalar gecersiz.");
            }

            ECPoint q = curve.G.Multiply(d).Normalize();
            var privateKey = new ECPrivateKeyParameters(d, domain);
            var publicKey = new ECPublicKeyParameters(q, domain);
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        public byte[] GetPublicKey()
        {
            if (_signingKeyPair?.Public == null)
            {
                throw new InvalidOperationException("Bu instance sadece dogrulama icin olusturuldu.");
            }

            var pub = (ECPublicKeyParameters)_signingKeyPair.Public;
            return pub.Q.GetEncoded(false);
        }

        public byte[] SignData(byte[] data)
        {
            if (_signingKeyPair?.Private == null)
            {
                throw new InvalidOperationException("Imza atabilmek icin private key gereklidir.");
            }

            var signer = new DsaDigestSigner(new ECDsaSigner(), new Sha256Digest());
            signer.Init(true, _signingKeyPair.Private);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        public bool VerifySignature(byte[] data, byte[] signature)
        {
            if (_trustedPublicKey == null)
            {
                throw new InvalidOperationException("Dogrulama icin onceden tanimli guvenilir bir anahtar gereklidir.");
            }

            try
            {
                var q = _curve.Curve.DecodePoint(_trustedPublicKey);
                if (q.IsInfinity || !q.IsValid())
                {
                    return false;
                }

                var verifier = new DsaDigestSigner(new ECDsaSigner(), new Sha256Digest());
                verifier.Init(false, new ECPublicKeyParameters(q, _domain));
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
