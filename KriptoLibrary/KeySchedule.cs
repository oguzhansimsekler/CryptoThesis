using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.Text;

namespace CryptoLibrary
{
    public static class KeySchedule
    {
        public const int OutputLength = 152;

        public record SessionKeyMaterial(
            byte[] ClientToServerKey,
            byte[] ClientToServerNonce,
            byte[] ServerToClientKey,
            byte[] ServerToClientNonce,
            byte[] ServerFinishedKey,
            byte[] ClientFinishedKey)
        {
            public void Clear()
            {
                CryptographicOperations.ZeroMemory(ClientToServerKey);
                CryptographicOperations.ZeroMemory(ClientToServerNonce);
                CryptographicOperations.ZeroMemory(ServerToClientKey);
                CryptographicOperations.ZeroMemory(ServerToClientNonce);
                CryptographicOperations.ZeroMemory(ServerFinishedKey);
                CryptographicOperations.ZeroMemory(ClientFinishedKey);
            }
        }

        // The input keying material is the X25519 secret followed by the ML-KEM secret;
        // transcriptHash is the HKDF salt.
        public static SessionKeyMaterial DeriveSessionKeys(byte[] inputKeyingMaterial, byte[] transcriptHash)
        {
            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            byte[] info = Encoding.UTF8.GetBytes("CryptoThesis-Protocol-v3-SessionKeys");
            hkdf.Init(new HkdfParameters(inputKeyingMaterial, transcriptHash, info));

            // 152 bytes: [0..43] client to server, [44..87] server to client,
            // [88..119] server Finished key, [120..151] client Finished key
            byte[] km = GC.AllocateArray<byte>(OutputLength, pinned: true);
            hkdf.GenerateBytes(km, 0, OutputLength);

            var keys = new SessionKeyMaterial(
                Pinned(km, 0, 32), Pinned(km, 32, 12),
                Pinned(km, 44, 32), Pinned(km, 76, 12),
                Pinned(km, 88, 32), Pinned(km, 120, 32));
            CryptographicOperations.ZeroMemory(km);
            return keys;
        }

        private static byte[] Pinned(byte[] source, int offset, int length)
        {
            byte[] result = GC.AllocateArray<byte>(length, pinned: true);
            Buffer.BlockCopy(source, offset, result, 0, length);
            return result;
        }
    }
}
