using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KriptoLibrary
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
    }
}