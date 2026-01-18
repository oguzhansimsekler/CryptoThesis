using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KriptoLibrary
{
    public class SecureChannel : IDisposable
    {
        private readonly byte[] _key;
        private readonly byte[] _nonceBase;
        private readonly AesGcm _aes;

        // Durum (State) takibi
        private ulong _outboundSequence = 0; // Gönderirken artar
        private ulong _expectedInboundSequence = 1; // Beklenen sıra numarası (Anti-Replay)

        public SecureChannel(byte[] key, byte[] nonceBase)
        {
            _key = key;
            _nonceBase = nonceBase;
            _aes = new AesGcm(_key);
        }

        public SecurePackage Encrypt(string plaintext)
        {
            _outboundSequence++;

            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] ciphertext = new byte[plaintextBytes.Length];
            byte[] tag = new byte[16];

            // Deterministik Nonce Üretimi: NonceBase XOR Sequence
            byte[] nonce = CalculateNonce(_outboundSequence);

            // AAD (Additional Authenticated Data): Sequence numarasını korumaya alıyoruz
            // Böylece saldırgan paketi kopyalayıp sırasını değiştiremez.
            byte[] aad = BitConverter.GetBytes(_outboundSequence);

            _aes.Encrypt(nonce, plaintextBytes, ciphertext, tag, aad);

            return new SecurePackage
            {
                Ciphertext = ciphertext,
                Tag = tag,
                Nonce = nonce,
                SequenceNumber = _outboundSequence
            };
        }

        public string Decrypt(SecurePackage package)
        {
            // 1. Anti-Replay Kontrolü (Stateful Check)
            if (package.SequenceNumber < _expectedInboundSequence)
                throw new Exception($"REPLAY ATTACK DETECTED! (Seq: {package.SequenceNumber}, Expected: {_expectedInboundSequence})");

            // 2. Şifre Çözme & Bütünlük (Integrity) Kontrolü
            byte[] plaintextBytes = new byte[package.Ciphertext.Length];
            byte[] aad = BitConverter.GetBytes(package.SequenceNumber);

            try
            {
                // Eğer veri bozulmuşsa (Tamper) bu satır CryptographicException fırlatır!
                _aes.Decrypt(package.Nonce, package.Ciphertext, package.Tag, plaintextBytes, aad);
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("INTEGRITY CHECK FAILED! Paket bozulmuş.");
            }

            // Başarılıysa beklenen sırayı artır
            _expectedInboundSequence = package.SequenceNumber + 1;

            return Encoding.UTF8.GetString(plaintextBytes);
        }

        private byte[] CalculateNonce(ulong seq)
        {
            byte[] nonce = (byte[])_nonceBase.Clone();
            byte[] seqBytes = BitConverter.GetBytes(seq);

            // Nonce'un ilk 8 byte'ını sequence ile XOR'la
            for (int i = 0; i < seqBytes.Length; i++)
            {
                nonce[i] ^= seqBytes[i];
            }
            return nonce;
        }

        public void Dispose()
        {
            _aes?.Dispose();
        }
    }
}
