using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoLibrary
{
    public static class ProtocolHelpers
    {
        public static byte[] CalculateCanonicalTranscriptHash(
            byte[] clientId, byte[] serverId,
            byte[] clientEph, byte[] serverEph)
        {
            var digest = new Sha256Digest();

            // Domain Separation
            byte[] domain = Encoding.ASCII.GetBytes("CTPK-HS1");
            digest.BlockUpdate(domain, 0, domain.Length);

            void UpdateWithLength(byte[] data)
            {
                byte[] lenBytes = new byte[2];
                // BigEndian Length Prefix
                BinaryPrimitives.WriteUInt16BigEndian(lenBytes, (ushort)data.Length);
                digest.BlockUpdate(lenBytes, 0, lenBytes.Length);
                digest.BlockUpdate(data, 0, data.Length);
            }

            UpdateWithLength(clientId);
            UpdateWithLength(serverId);
            UpdateWithLength(clientEph);
            UpdateWithLength(serverEph);

            byte[] output = new byte[32];
            digest.DoFinal(output, 0);
            return output;
        }

        public static byte[] BuildHandshakeTranscript(
        byte[] clientNonce, byte[] serverNonce,
        byte[] clientEph, byte[] serverEph)
        {
            byte[] label = System.Text.Encoding.UTF8.GetBytes("WASM-AKE-V1");
            // Canonical serialization (Label + N1 + N2 + PK1 + PK2)
            return Combine(label, clientNonce, serverNonce, clientEph, serverEph);
        }

        private static byte[] Combine(params byte[][] arrays)
        {
            byte[] rv = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays)
            {
                Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }
    }

    public class HandshakeMessage
    {
        public Guid SessionId { get; set; }
        public byte[] Nonce { get; set; } = Array.Empty<byte>();
        public byte[] EphemeralPublicKey { get; set; } = Array.Empty<byte>();
        public byte[]? Signature { get; set; } // Sadece ServerHello'da dolu gelir
    }

}
