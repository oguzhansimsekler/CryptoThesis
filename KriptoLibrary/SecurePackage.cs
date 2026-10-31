using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoLibrary
{
    public class SecurePackage
    {
        public ulong SequenceNumber { get; set; }
        public byte[] Nonce { get; set; } = Array.Empty<byte>();
        public byte[] Ciphertext { get; set; } = Array.Empty<byte>();
        public byte[] Tag { get; set; } = Array.Empty<byte>();
    }
}
