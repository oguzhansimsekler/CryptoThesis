using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Text;

namespace CryptoLibrary
{
    public static class ProtocolHelpers
    {
        public static byte[] GetAnonymousIdentityPlaceholder() => new byte[32];

        // HKDF salt. Covers the same values as the signed transcript, in a different encoding.
        public static byte[] CalculateCanonicalTranscriptHash(
            byte[] clientId,
            byte[] serverId,
            byte[] clientEph,
            byte[] serverEph,
            byte[] kemEncapsulationKey,
            byte[] kemCiphertext,
            byte[] clientNonce,
            byte[] serverNonce)
        {
            var digest = new Sha256Digest();
            byte[] domain = Encoding.ASCII.GetBytes("CTPK-HS3");
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
            UpdateWithLength(kemEncapsulationKey);
            UpdateWithLength(kemCiphertext);
            UpdateWithLength(clientNonce);
            UpdateWithLength(serverNonce);

            byte[] output = new byte[32];
            digest.DoFinal(output, 0);
            return output;
        }

        // The byte string the server signs with its Ed25519 identity key.
        public static byte[] BuildHandshakeTranscript(
            byte[] clientNonce,
            byte[] serverNonce,
            byte[] clientEph,
            byte[] serverEph,
            byte[] kemEncapsulationKey,
            byte[] kemCiphertext,
            byte[] serverIdentityPub)
        {
            byte[] label = Encoding.UTF8.GetBytes("WASM-AKE-V3");
            return CombineWithLength(label, clientNonce, serverNonce, clientEph, serverEph,
                kemEncapsulationKey, kemCiphertext, serverIdentityPub);
        }

        public static byte[] ComputeServerFinished(byte[] serverFinishedKey, byte[] transcriptHash, byte[] signature) =>
            Hmac(serverFinishedKey, CombineWithLength(Encoding.ASCII.GetBytes("server finished"), transcriptHash, signature));

        public static byte[] ComputeClientFinished(byte[] clientFinishedKey, byte[] transcriptHash, byte[] signature, byte[] serverFinished) =>
            Hmac(clientFinishedKey, CombineWithLength(Encoding.ASCII.GetBytes("client finished"), transcriptHash, signature, serverFinished));

        public static bool FixedTimeEquals(byte[] a, byte[] b) =>
            a != null && b != null && Org.BouncyCastle.Utilities.Arrays.FixedTimeEquals(a, b);

        private static byte[] Hmac(byte[] key, byte[] data)
        {
            var mac = new HMac(new Sha256Digest());
            mac.Init(new KeyParameter(key));
            mac.BlockUpdate(data, 0, data.Length);
            byte[] output = new byte[mac.GetMacSize()];
            mac.DoFinal(output, 0);
            return output;
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
        public byte[] KemEncapsulationKey { get; set; } = Array.Empty<byte>();
    }

    public class ServerHelloMessage
    {
        public Guid SessionId { get; set; }
        public byte[] ServerNonce { get; set; } = Array.Empty<byte>();
        public byte[] ServerEphemeralPublicKey { get; set; } = Array.Empty<byte>();
        public byte[] KemCiphertext { get; set; } = Array.Empty<byte>();
        public byte[] ServerIdentityPublicKey { get; set; } = Array.Empty<byte>();
        public byte[] Signature { get; set; } = Array.Empty<byte>();
        public byte[] ServerFinished { get; set; } = Array.Empty<byte>();
    }

    public class ClientFinishedMessage
    {
        public Guid SessionId { get; set; }
        public byte[] ClientFinished { get; set; } = Array.Empty<byte>();
    }

    public class DeliveryReport
    {
        public bool Success { get; set; }
        public string StatusMessage { get; set; } = string.Empty;

        // The server's echo of the accepted message, encrypted on the server-to-client channel.
        public SecurePackage? EncryptedEcho { get; set; }
    }
}
