namespace CryptoLibrary
{
    using System;

    public class CryptoProtocolSession
    {
        public string Role { get; }
        public IdentityService Identity { get; }
        public HandshakeService Handshake { get; }

        public SecureChannel? SendChannel { get; private set; }
        public SecureChannel? ReceiveChannel { get; private set; }

        public byte[]? MyEphemeralPub { get; }
        public byte[]? PeerEphemeralPub { get; private set; }
        public byte[]? TranscriptHash { get; private set; }

        public CryptoProtocolSession(IdentityService identity, string role)
        {
            Role = role;
            Identity = identity;
            Handshake = new HandshakeService();
            MyEphemeralPub = Handshake.GetPublicKey();
        }

        public void FinalizeHandshake(byte[] peerIdentityPub, byte[] peerEphPub, byte[] clientNonce, byte[] serverNonce)
        {
            PeerEphemeralPub = peerEphPub;
            byte[] sharedSecret = Handshake.DeriveSharedSecret(peerEphPub);

            byte[] clientId;
            byte[] serverId;
            byte[] clientEph;
            byte[] serverEph;

            if (Role == "Client")
            {
                clientId = TryGetOwnPublicKeyOrAnonymous();
                serverId = peerIdentityPub;
                clientEph = MyEphemeralPub!;
                serverEph = peerEphPub;
            }
            else
            {
                clientId = peerIdentityPub.Length == 0 ? ProtocolHelpers.GetAnonymousIdentityPlaceholder() : peerIdentityPub;
                serverId = Identity.GetPublicKey();
                clientEph = peerEphPub;
                serverEph = MyEphemeralPub!;
            }

            TranscriptHash = ProtocolHelpers.CalculateCanonicalTranscriptHash(
                clientId, serverId, clientEph, serverEph, clientNonce, serverNonce);

            var keys = KeySchedule.DeriveSessionKeys(sharedSecret, TranscriptHash);
            bool isClient = Role == "Client";

            // The client sends with the client-to-server key; the server does the opposite.
            SendChannel = new SecureChannel(
                isClient ? keys.ClientToServerKey   : keys.ServerToClientKey,
                isClient ? keys.ClientToServerNonce : keys.ServerToClientNonce);

            ReceiveChannel = new SecureChannel(
                isClient ? keys.ServerToClientKey   : keys.ClientToServerKey,
                isClient ? keys.ServerToClientNonce : keys.ClientToServerNonce);
        }

        private byte[] TryGetOwnPublicKeyOrAnonymous()
        {
            try { return Identity.GetPublicKey(); }
            catch { return ProtocolHelpers.GetAnonymousIdentityPlaceholder(); }
        }
    }
}
