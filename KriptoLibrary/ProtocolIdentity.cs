namespace CryptoLibrary
{
    using System;

    public static class ProtocolIdentity
    {
        // Tez demosunda client'a out-of-band olarak pin edilen sunucu public anahtarının türetildiği seed.
        // Sunucunun private seed'i artık bu sınıfta tutulmaz; appsettings.json / ortam değişkeni ile yapılandırılır.
        // Bu sabit yalnızca pinned public key'i türetmek için kullanılır ve gizli değildir.
        internal const string DemoServerSeedHex = "1E99423A4ED27608A15A2616DE1B5B3F4A8E7D3C2B1A09182736455463728190";

        private static readonly Lazy<byte[]> PinnedServerPublicKeyLazy = new(
            () => IdentityService.CreateFromPrivateSeed(Convert.FromHexString(DemoServerSeedHex)).GetPublicKey());

        public static byte[] GetPinnedServerPublicKey() => (byte[])PinnedServerPublicKeyLazy.Value.Clone();
    }
}
