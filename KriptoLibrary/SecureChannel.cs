using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace CryptoLibrary
{
    /// <summary>When the receiver compares the sequence number with the expected one.</summary>
    public enum SequenceCheckOrder
    {
        // Default: the tag is verified first, so a modified record is always reported as an integrity failure.
        AfterAuthentication,
        // The cheap comparison runs first; used to show that the rejecting check depends on this choice.
        BeforeAuthentication
    }

    public sealed class SecureChannel : IDisposable
    {
        public const int TagSize = 16;
        private const int NonceSize = 12;

        private readonly byte[] _key;
        private readonly byte[] _nonceBase;
        private readonly SequenceCheckOrder _order;
        private ulong _outboundSequence = 0;
        private ulong _expectedInboundSequence = 1; // sequence numbers start at 1
        private bool _disposed;

        public SecureChannel(byte[] key, byte[] nonceBase, SequenceCheckOrder order = SequenceCheckOrder.AfterAuthentication)
        {
            if (key == null || key.Length != 32 || nonceBase == null || nonceBase.Length != NonceSize)
                throw new ArgumentException("AES-256-GCM needs a 32-byte key and a 12-byte nonce base.");

            // Own pinned copies, so the garbage collector does not move them and they can be cleared.
            _key = GC.AllocateArray<byte>(key.Length, pinned: true);
            _nonceBase = GC.AllocateArray<byte>(nonceBase.Length, pinned: true);
            key.CopyTo(_key, 0);
            nonceBase.CopyTo(_nonceBase, 0);
            _order = order;
        }

        public SecurePackage Encrypt(byte[] plaintext)
        {
            ThrowIfDisposed();
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));
            if (_outboundSequence == ulong.MaxValue)
                throw new InvalidOperationException("KANAL SINIRINA ULAŞILDI: maksimum mesaj sayısı aşıldı. Oturum yenilenmeli.");

            _outboundSequence++;

            // Hardware AES where the CPU offers it (constant-time); table-based AES otherwise,
            // which includes WebAssembly.
            var cipher = new GcmBlockCipher(AesUtilities.CreateEngine());
            cipher.Init(true, new AeadParameters(new KeyParameter(_key), TagSize * 8, CalculateNonce(_outboundSequence), Aad(_outboundSequence)));

            byte[] output = new byte[cipher.GetOutputSize(plaintext.Length)];
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            cipher.DoFinal(output, len);

            // BouncyCastle output: ciphertext followed by the 16-byte tag
            return new SecurePackage
            {
                SequenceNumber = _outboundSequence,
                Ciphertext = output[..^TagSize],
                Tag = output[^TagSize..]
            };
        }

        public byte[] Decrypt(SecurePackage package)
        {
            ThrowIfDisposed();
            if (package == null || package.Ciphertext == null || package.Tag == null || package.Tag.Length != TagSize)
                throw new Exception("PAKET BOZUK! (Eksik Veri)");

            if (_order == SequenceCheckOrder.BeforeAuthentication)
                CheckSequence(package.SequenceNumber);

            byte[] input = new byte[package.Ciphertext.Length + TagSize];
            package.Ciphertext.CopyTo(input, 0);
            package.Tag.CopyTo(input, package.Ciphertext.Length);

            // The nonce is not sent; it follows from the claimed sequence number,
            // which is also the associated data.
            var cipher = new GcmBlockCipher(AesUtilities.CreateEngine());
            byte[] plaintext;

            try
            {
                cipher.Init(false, new AeadParameters(new KeyParameter(_key), TagSize * 8, CalculateNonce(package.SequenceNumber), Aad(package.SequenceNumber)));
                byte[] buffer = new byte[cipher.GetOutputSize(input.Length)];
                int len = cipher.ProcessBytes(input, 0, input.Length, buffer, 0);
                len += cipher.DoFinal(buffer, len); // throws here if the tag does not match
                plaintext = buffer[..len];
            }
            catch (Exception)
            {
                throw new Exception("BÜTÜNLÜK HATASI! (Tag Mismatch - Veri Değiştirilmiş)");
            }

            if (_order == SequenceCheckOrder.AfterAuthentication)
                CheckSequence(package.SequenceNumber);

            _expectedInboundSequence++;
            return plaintext;
        }

        // UTF-8 helpers for applications that exchange text. The encoding runs outside the
        // AEAD call, and its timing depends on the content of the text.
        public SecurePackage EncryptText(string plaintext) => Encrypt(Encoding.UTF8.GetBytes(plaintext));

        public string DecryptText(SecurePackage package) => Encoding.UTF8.GetString(Decrypt(package));

        public void Dispose()
        {
            if (_disposed) return;
            CryptographicOperations.ZeroMemory(_key);
            CryptographicOperations.ZeroMemory(_nonceBase);
            _disposed = true;
        }

        private void CheckSequence(ulong sequenceNumber)
        {
            if (sequenceNumber != _expectedInboundSequence)
                throw new Exception($"REPLAY SALDIRISI! (Seq: {sequenceNumber} Beklenen: {_expectedInboundSequence})");
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(SecureChannel));
        }

        private static byte[] Aad(ulong sequenceNumber)
        {
            byte[] aad = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(aad, sequenceNumber);
            return aad;
        }

        // As in TLS 1.3: the 64-bit sequence number, left-padded to 12 bytes, XORed with the nonce base,
        // so it changes the last 8 bytes.
        private byte[] CalculateNonce(ulong sequenceNumber)
        {
            byte[] nonce = (byte[])_nonceBase.Clone();
            Span<byte> seq = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(seq, sequenceNumber);
            for (int i = 0; i < 8; i++)
                nonce[NonceSize - 8 + i] ^= seq[i];
            return nonce;
        }
    }
}
