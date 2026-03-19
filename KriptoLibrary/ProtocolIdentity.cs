namespace CryptoLibrary
{
    using System;

    public static class ProtocolIdentity
    {
        // Tez demosu icin out-of-band olarak paylasilan ve istemciye pin edilen sabit sunucu kimligi.
        private const string ServerPrivateScalarHex = "1E99423A4ED27608A15A2616DE1B5B3F4A8E7D3C2B1A09182736455463728190";

        private static readonly Lazy<IdentityService> ServerIdentityLazy =
            new(() => new IdentityService(
                IdentityService.CreateLongTermKeyPairFromPrivateScalar(Convert.FromHexString(ServerPrivateScalarHex))));

        private static readonly Lazy<byte[]> PinnedServerPublicKeyLazy =
            new(() => ServerIdentityLazy.Value.GetPublicKey());

        public static IdentityService CreateServerIdentity() => ServerIdentityLazy.Value;

        public static byte[] GetPinnedServerPublicKey() => (byte[])PinnedServerPublicKeyLazy.Value.Clone();
    }
}
