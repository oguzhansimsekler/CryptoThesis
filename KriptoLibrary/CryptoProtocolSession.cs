namespace KriptoLibrary
{
    using CryptoLibrary;
    using System;
    using System.Linq;

    public class CryptoProtocolSession
    {
        public string Role { get; }
        public IdentityService Identity { get; }
        public HandshakeService Handshake { get; }
        public SecureChannel? Channel { get; private set; }

        public byte[]? MyEphemeralPub { get; }
        public byte[]? PeerEphemeralPub { get; private set; }
        public byte[]? TranscriptHash { get; private set; }

        // Constructor artık zorunlu olarak bir IdentityService bekler (CS1503 ve CS1729 çözümü).
        public CryptoProtocolSession(IdentityService identity, string role)
        {
            Role = role;
            Identity = identity;
            Handshake = new HandshakeService();
            MyEphemeralPub = Handshake.GetPublicKey();
        }

        public void FinalizeHandshake(byte[] peerIdentityPub, byte[] peerEphPub)
        {
            this.PeerEphemeralPub = peerEphPub;

            // 1. Shared Secret Türet (ECDH)
            byte[] sharedSecret = Handshake.DeriveSharedSecret(peerEphPub);

            // 2. Transcript İçin Kimlikleri Hazırla
            byte[] clientID, serverID, clientEph, serverEph;

            if (Role == "Client")
            {
                // ALICE: Kendi kimliği yoksa (Anonymous) hata fırlatmak yerine boş dizi kullan
                try
                {
                    clientID = Identity.GetPublicKey();
                }
                catch
                {
                    clientID = new byte[65]; // 65 byte'lık dummy ID
                }

                serverID = peerIdentityPub;
                clientEph = MyEphemeralPub!;
                serverEph = peerEphPub;
            }
            else // BOB (Server)
            {
                clientID = peerIdentityPub; // Alice'den gelen (boş) ID
                serverID = Identity.GetPublicKey();
                clientEph = peerEphPub;
                serverEph = MyEphemeralPub!;
            }

            // 3. Transcript Hash ve Anahtar Türetme (Geri kalanı aynı)
            TranscriptHash = ProtocolHelpers.CalculateCanonicalTranscriptHash(clientID, serverID, clientEph, serverEph);
            var keys = KeySchedule.DeriveSessionKeys(sharedSecret, TranscriptHash);
            Channel = new SecureChannel(keys.Key, keys.NonceBase);
        }
    }
}