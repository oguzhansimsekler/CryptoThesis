using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoLibrary
{
    public class SecurePackage
    {
        public ulong SequenceNumber { get; set; } // Replay Attack koruması için
        public byte[] Nonce { get; set; }         // Her mesajda değişen IV
        public byte[] Ciphertext { get; set; }    // Şifreli veri
        public byte[] Tag { get; set; }           // Bütünlük (Integrity) etiketi
    }
}
