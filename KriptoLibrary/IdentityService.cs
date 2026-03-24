namespace CryptoLibrary
{
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Crypto.Signers;
    using Org.BouncyCastle.Security;
    using System;

    /// <summary>
    /// Ed25519 tabanli uzun donem kimlik anahtarlarini ve imza dogrulama akislarini yonetir.
    /// </summary>
    public class IdentityService
    {
        private const int Ed25519KeySize = 32;
        private readonly Ed25519PrivateKeyParameters? _privateKey;
        private readonly Ed25519PublicKeyParameters? _publicKey;
        private readonly byte[]? _trustedPublicKey;

        public bool HasSigningKey => _privateKey != null;

        public IdentityService(Ed25519PrivateKeyParameters privateKey)
        {
            _privateKey = privateKey;
            _publicKey = privateKey.GeneratePublicKey();
        }

        public IdentityService(byte[] trustedPublicKey)
        {
            _trustedPublicKey = trustedPublicKey;
        }

        public static IdentityService GenerateLongTermIdentity()
        {
            return new IdentityService(new Ed25519PrivateKeyParameters(new SecureRandom()));
        }

        public static IdentityService CreateFromPrivateSeed(byte[] seed)
        {
            if (seed == null || seed.Length != Ed25519KeySize)
            {
                throw new ArgumentException("Ed25519 private seed gecersiz.");
            }

            return new IdentityService(new Ed25519PrivateKeyParameters(seed, 0));
        }

        public byte[] GetPublicKey()
        {
            if (_publicKey == null)
            {
                throw new InvalidOperationException("Bu instance sadece dogrulama icin olusturuldu.");
            }

            byte[] output = new byte[Ed25519KeySize];
            _publicKey.Encode(output, 0);
            return output;
        }

        public byte[] SignData(byte[] data)
        {
            if (_privateKey == null)
            {
                throw new InvalidOperationException("Imza atabilmek icin private key gereklidir.");
            }

            var signer = new Ed25519Signer();
            signer.Init(true, _privateKey);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        public bool VerifySignature(byte[] data, byte[] signature)
        {
            if (_trustedPublicKey == null || _trustedPublicKey.Length != Ed25519KeySize)
            {
                throw new InvalidOperationException("Dogrulama icin onceden tanimli guvenilir bir anahtar gereklidir.");
            }

            try
            {
                var verifier = new Ed25519Signer();
                verifier.Init(false, new Ed25519PublicKeyParameters(_trustedPublicKey, 0));
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
