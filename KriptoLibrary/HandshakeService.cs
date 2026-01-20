using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Math.EC; // ECPoint için gerekli

namespace CryptoLibrary
{
    public class HandshakeService
    {
        private readonly AsymmetricCipherKeyPair _ephemeralKeyPair;
        private readonly X9ECParameters _curve;
        private readonly ECDomainParameters _domain;

        public HandshakeService()
        {
            _curve = ECNamedCurveTable.GetByName("secp256r1");
            _domain = new ECDomainParameters(_curve.Curve, _curve.G, _curve.N, _curve.H);

            var gen = new ECKeyPairGenerator();
            var secureRandom = new SecureRandom();
            var keyGenParam = new ECKeyGenerationParameters(_domain, secureRandom);
            gen.Init(keyGenParam);
            _ephemeralKeyPair = gen.GenerateKeyPair();
        }

        public byte[] GetPublicKey()
        {
            var pub = (ECPublicKeyParameters)_ephemeralKeyPair.Public;
            return pub.Q.GetEncoded(false);
        }

        public byte[] DeriveSharedSecret(byte[] otherPublicKeyBytes)
        {
            ECPoint q;
            try
            {
                q = _curve.Curve.DecodePoint(otherPublicKeyBytes);
            }
            catch (Exception)
            {
                throw new Exception("HANDSHAKE HATASI: Public Key formatı geçersiz.");
            }

            // GÜVENLİK KONTROLÜ 4.1: Sonsuz (Infinity) veya Geçersiz Nokta Kontrolü
            if (q.IsInfinity || !q.IsValid())
                throw new Exception("HANDSHAKE SALDIRISI: Geçersiz veya 'Infinity' nokta tespit edildi.");

            var otherPubKey = new ECPublicKeyParameters(q, _domain);

            IBasicAgreement agreement = AgreementUtilities.GetBasicAgreement("ECDH");
            agreement.Init(_ephemeralKeyPair.Private);

            var secretBigInt = agreement.CalculateAgreement(otherPubKey);

            // Shared Secret her zaman 32 byte olmalı (Padding)
            return ToFixed32(secretBigInt.ToByteArrayUnsigned());
        }

        // OPTİMİZASYON: Buffer.BlockCopy ile daha az bellek tahsisi
        private static byte[] ToFixed32(byte[] input)
        {
            var out32 = new byte[32];

            if (input.Length >= 32)
            {
                // Eğer 32 veya daha büyükse, son 32 byte'ı al
                Buffer.BlockCopy(input, input.Length - 32, out32, 0, 32);
            }
            else
            {
                // Eğer 32'den küçükse, baş tarafı 0 ile doldur (Pad Left)
                // out32 zaten 0 ile initialize edildi, sadece veriyi sağa yasla.
                Buffer.BlockCopy(input, 0, out32, 32 - input.Length, input.Length);
            }

            return out32;
        }
    }
}