using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KriptoLibrary
{
    public class Models
    {
        public class ClientHelloMessage
        {
            public byte[] ClientNonce { get; set; } = Array.Empty<byte>();
            public byte[] ClientEphemeralPublicKey { get; set; } = Array.Empty<byte>();
        }

        public class ServerHelloMessage
        {
            public byte[] ServerNonce { get; set; } = Array.Empty<byte>();
            public byte[] ServerEphemeralPublicKey { get; set; } = Array.Empty<byte>();
            public byte[] Signature { get; set; } = Array.Empty<byte>(); // Transcript imzası
        }
    }
}
