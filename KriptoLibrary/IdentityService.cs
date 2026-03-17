namespace CryptoLibrary
{
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Asn1.X9;
    using Org.BouncyCastle.Crypto.Digests;
    using Org.BouncyCastle.Crypto.Signers;
    using System;

    /// <summary>
    /// Kimlik doğrulama (Authentication) işlemlerini yürüten servis.
    /// Uzun ömürlü ECDSA anahtarlarını ve dijital imza süreçlerini yönetir.
    /// </summary>
    public class IdentityService
    {
        private readonly AsymmetricCipherKeyPair? _signingKeyPair;
        private readonly byte[]? _trustedPublicKey;
        private readonly X9ECParameters _curve;
        private readonly ECDomainParameters _domain;
        public bool HasSigningKey => _signingKeyPair != null;
        // SUNUCU ROLÜ: Kendi özel anahtarıyla imza atmak için kullanılır (Long-term identity)[cite: 1, 157].

        private static readonly IdentityService StaticBobIdentity = new IdentityService(IdentityService.GenerateLongTermKeyPair());
        public IdentityService(AsymmetricCipherKeyPair signingKeyPair)
        {
            _curve = ECNamedCurveTable.GetByName("secp256r1");
            _domain = new ECDomainParameters(_curve.Curve, _curve.G, _curve.N, _curve.H);
            _signingKeyPair = signingKeyPair;
        }

        // İSTEMCİ ROLÜ: Sadece önceden bildiği güvenilir açık anahtarla doğrular (Trust Anchor) [cite: 1, 314-321].
        public IdentityService(byte[] trustedPublicKey)
        {
            _curve = ECNamedCurveTable.GetByName("secp256r1");
            _domain = new ECDomainParameters(_curve.Curve, _curve.G, _curve.N, _curve.H);
            _trustedPublicKey = trustedPublicKey;
        }

        // Home.razor ve Hub tarafındaki CS1729 hatasını çözen yardımcı metot.
        public static AsymmetricCipherKeyPair GenerateLongTermKeyPair()
        {
            var curve = ECNamedCurveTable.GetByName("secp256r1");
            var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var gen = new ECKeyPairGenerator();
            gen.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
            return gen.GenerateKeyPair();
        }

        public byte[] GetPublicKey()
        {
            if (_signingKeyPair?.Public == null)
                throw new InvalidOperationException("Bu instance sadece doğrulama için oluşturuldu.");

            var pub = (Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters)_signingKeyPair.Public;
            return pub.Q.GetEncoded(false);
        }

        public byte[] SignData(byte[] data)
        {
            if (_signingKeyPair?.Private == null)
                throw new InvalidOperationException("İmza atabilmek için Private Key gereklidir.");

            var signer = new DsaDigestSigner(new ECDsaSigner(), new Sha256Digest());
            signer.Init(true, _signingKeyPair.Private);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        public bool VerifySignature(byte[] data, byte[] signature)
        {
            if (_trustedPublicKey == null)
                throw new InvalidOperationException("Doğrulama için önceden tanımlı güvenilir bir anahtar gereklidir.");

            try
            {
                var q = _curve.Curve.DecodePoint(_trustedPublicKey);
                var verifier = new DsaDigestSigner(new ECDsaSigner(), new Sha256Digest());
                verifier.Init(false, new ECPublicKeyParameters(q, _domain));
                verifier.BlockUpdate(data, 0, data.Length);
                return verifier.VerifySignature(signature);
            }
            catch { return false; }
        }
    }
}