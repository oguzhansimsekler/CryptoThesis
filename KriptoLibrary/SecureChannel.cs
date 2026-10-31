using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Buffers.Binary;
using System.Text;

namespace CryptoLibrary
{
    public class SecureChannel
    {
        private readonly byte[] _key;
        private readonly byte[] _nonceBase;
        private ulong _outboundSequence = 0;
        private ulong _expectedInboundSequence = 1; // sequence numbers start at 1

        public SecureChannel(byte[] key, byte[] nonceBase)
        {
            _key = key;
            _nonceBase = nonceBase;
        }

        public SecurePackage Encrypt(string plaintext)
        {
            if (_outboundSequence == ulong.MaxValue)
                throw new InvalidOperationException("KANAL SINIRINA ULAŞILDI: maksimum mesaj sayısı aşıldı. Oturum yenilenmeli.");

            _outboundSequence++;

            byte[] nonce = CalculateNonce(_outboundSequence);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

            byte[] aad = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(aad, _outboundSequence);

            // Hardware AES where the CPU offers it (constant-time); table-based AES otherwise,
            // which includes WebAssembly.
            var cipher = new GcmBlockCipher(AesUtilities.CreateEngine());
            var parameters = new AeadParameters(new KeyParameter(_key), 128, nonce, aad);
            cipher.Init(true, parameters);

            byte[] output = new byte[cipher.GetOutputSize(plaintextBytes.Length)];
            int len = cipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, output, 0);
            cipher.DoFinal(output, len);

            // BouncyCastle output: ciphertext followed by the 16-byte tag
            int tagSize = 16;
            int ciphertextSize = output.Length - tagSize;

            byte[] ciphertext = new byte[ciphertextSize];
            byte[] tag = new byte[tagSize];

            Array.Copy(output, 0, ciphertext, 0, ciphertextSize);
            Array.Copy(output, ciphertextSize, tag, 0, tagSize);

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
            if (package == null || package.Ciphertext == null || package.Tag == null || package.Nonce == null)
            {
                throw new Exception("PAKET BOZUK! (Eksik Veri)");
            }

            byte[] aad = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(aad, package.SequenceNumber);

            byte[] input = new byte[package.Ciphertext.Length + package.Tag.Length];
            Array.Copy(package.Ciphertext, 0, input, 0, package.Ciphertext.Length);
            Array.Copy(package.Tag, 0, input, package.Ciphertext.Length, package.Tag.Length);

            var cipher = new GcmBlockCipher(AesUtilities.CreateEngine());
            var parameters = new AeadParameters(new KeyParameter(_key), 128, package.Nonce, aad);

            string plaintext = "";

            try
            {
                cipher.Init(false, parameters);
                byte[] plaintextBytes = new byte[cipher.GetOutputSize(input.Length)];

                int len = cipher.ProcessBytes(input, 0, input.Length, plaintextBytes, 0);
                len += cipher.DoFinal(plaintextBytes, len); // throws here if the tag does not match

                plaintext = Encoding.UTF8.GetString(plaintextBytes, 0, len);
            }
            catch (Exception)
            {
                throw new Exception("BÜTÜNLÜK HATASI! (Tag Mismatch - Veri Değiştirilmiş)");
            }

            // The sequence check runs only after the tag has been verified.
            if (package.SequenceNumber != _expectedInboundSequence)
            {
                throw new Exception($"REPLAY SALDIRISI! (Seq: {package.SequenceNumber} Beklenen: {_expectedInboundSequence})");
            }

            _expectedInboundSequence++;

            return plaintext;
        }
        private byte[] CalculateNonce(ulong seq)
        {
            byte[] nonce = (byte[])_nonceBase.Clone();
            byte[] seqBytes = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(seqBytes, seq);

            // XOR the sequence number into the first 8 bytes of the nonce base.
            for (int i = 0; i < 8; i++)
            {
                nonce[i] ^= seqBytes[i];
            }
            return nonce;
        }
    }
}
