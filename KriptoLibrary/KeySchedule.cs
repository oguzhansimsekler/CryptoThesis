using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
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
            byte[] ClientFinishedKey);

        // The input keying material is the X25519 secret followed by the ML-KEM secret;
        // transcriptHash is the HKDF salt.
        public static SessionKeyMaterial DeriveSessionKeys(byte[] inputKeyingMaterial, byte[] transcriptHash)
        {
            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            byte[] info = Encoding.UTF8.GetBytes("CryptoThesis-Protocol-v3-SessionKeys");
            hkdf.Init(new HkdfParameters(inputKeyingMaterial, transcriptHash, info));

            // 152 bytes: [0..43] client to server, [44..87] server to client,
            // [88..119] server Finished key, [120..151] client Finished key
            byte[] km = new byte[OutputLength];
            hkdf.GenerateBytes(km, 0, OutputLength);

            return new SessionKeyMaterial(
                km[0..32], km[32..44],
                km[44..76], km[76..88],
                km[88..120], km[120..152]);
        }
    }
}
