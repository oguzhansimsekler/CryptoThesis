namespace CryptoLibrary
{
    // The nonce is not part of the record: both sides derive it from the sequence number.
    public class SecurePackage
    {
        public ulong SequenceNumber { get; set; }
        public byte[] Ciphertext { get; set; } = Array.Empty<byte>();
        public byte[] Tag { get; set; } = Array.Empty<byte>();
    }
}
