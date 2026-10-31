namespace CryptoLibrary
{
    using System;

    public static class ProtocolIdentity
    {
        // Demo seed. The client's pinned public key is derived from it; the server reads its
        // own seed from configuration. Not a secret; replace it for any real use.
        internal const string DemoServerSeedHex = "1E99423A4ED27608A15A2616DE1B5B3F4A8E7D3C2B1A09182736455463728190";

        private static readonly Lazy<byte[]> PinnedServerPublicKeyLazy = new(
            () => IdentityService.CreateFromPrivateSeed(Convert.FromHexString(DemoServerSeedHex)).GetPublicKey());

        public static byte[] GetPinnedServerPublicKey() => (byte[])PinnedServerPublicKeyLazy.Value.Clone();
    }
}
