using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Text;

namespace CryptoLibrary
{
    public static class ProtocolHelpers
    {
        public static byte[] GetAnonymousIdentityPlaceholder() => new byte[65];

        public static byte[] CalculateCanonicalTranscriptHash(
            byte[] clientId,
            byte[] serverId,
            byte[] clientEph,
            byte[] serverEph,
            byte[] clientNonce,
            byte[] serverNonce)
        {
            var digest = new Sha256Digest();
            byte[] domain = Encoding.ASCII.GetBytes("CTPK-HS1");
            digest.BlockUpdate(domain, 0, domain.Length);

            void UpdateWithLength(byte[] data)
            {
                byte[] lenBytes = new byte[2];
                BinaryPrimitives.WriteUInt16BigEndian(lenBytes, (ushort)data.Length);
                digest.BlockUpdate(lenBytes, 0, lenBytes.Length);
                digest.BlockUpdate(data, 0, data.Length);
            }

            UpdateWithLength(clientId);
            UpdateWithLength(serverId);
            UpdateWithLength(clientEph);
            UpdateWithLength(serverEph);
            UpdateWithLength(clientNonce);
            UpdateWithLength(serverNonce);

            byte[] output = new byte[32];
            digest.DoFinal(output, 0);
            return output;
        }

        public static byte[] BuildHandshakeTranscript(
            byte[] clientNonce,
            byte[] serverNonce,
            byte[] clientEph,
            byte[] serverEph,
            byte[] serverIdentityPub)
        {
            byte[] label = Encoding.UTF8.GetBytes("WASM-AKE-V2");
            return CombineWithLength(label, clientNonce, serverNonce, clientEph, serverEph, serverIdentityPub);
        }

        private static byte[] CombineWithLength(params byte[][] arrays)
        {
            int totalLength = arrays.Sum(a => a.Length + 2);
            byte[] rv = new byte[totalLength];
            int offset = 0;

            foreach (byte[] array in arrays)
            {
                BinaryPrimitives.WriteUInt16BigEndian(rv.AsSpan(offset, 2), (ushort)array.Length);
                offset += 2;
                Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }

            return rv;
        }
    }

    public class ClientHelloMessage
    {
        public Guid SessionId { get; set; }
        public byte[] ClientNonce { get; set; } = Array.Empty<byte>();
        public byte[] ClientEphemeralPublicKey { get; set; } = Array.Empty<byte>();
    }

    public class ServerHelloMessage
    {
        public Guid SessionId { get; set; }
        public byte[] ServerNonce { get; set; } = Array.Empty<byte>();
        public byte[] ServerEphemeralPublicKey { get; set; } = Array.Empty<byte>();
        public byte[] ServerIdentityPublicKey { get; set; } = Array.Empty<byte>();
        public byte[] Signature { get; set; } = Array.Empty<byte>();
    }

    public class DeliveryReport
    {
        public bool Success { get; set; }
        public string StatusMessage { get; set; } = string.Empty;
        public string? Plaintext { get; set; }
    }
}
