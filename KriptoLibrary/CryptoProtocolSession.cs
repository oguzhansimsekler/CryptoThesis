using CryptoLibrary;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KriptoLibrary
{
    public class CryptoProtocolSession
    {
        public string Role { get; } // "Client" veya "Server"

        // Alt Modüller
        public IdentityService Identity { get; private set; }
        public HandshakeService Handshake { get; private set; }
        public SecureChannel? Channel { get; private set; }

        // Durum Bilgisi (State)
        public byte[]? MyEphemeralPub { get; private set; }
        public byte[]? PeerEphemeralPub { get; private set; }
        public byte[]? TranscriptHash { get; private set; }

        public CryptoProtocolSession(string role)
        {
            Role = role;
            Identity = new IdentityService();
            Handshake = new HandshakeService();
            // Kendi geçici anahtarımızı oluşturuyoruz
            MyEphemeralPub = Handshake.GetPublicKey();
        }

        /// <summary>
        /// Handshake işlemini tamamlar ve SecureChannel oluşturur.
        /// </summary>
        public void FinalizeHandshake(byte[] peerIdentityPub, byte[] peerEphPub)
        {
            this.PeerEphemeralPub = peerEphPub;

            // 1. Shared Secret Türet
            byte[] sharedSecret = Handshake.DeriveSharedSecret(peerEphPub);

            // 2. Canonical Transcript Hash Hesapla (Sıralama Önemli!)
            byte[] clientID, serverID, clientEph, serverEph;

            if (Role == "Client")
            {
                clientID = Identity.GetPublicKey();
                serverID = peerIdentityPub;
                clientEph = MyEphemeralPub!;
                serverEph = peerEphPub;
            }
            else // Server
            {
                clientID = peerIdentityPub;
                serverID = Identity.GetPublicKey();
                clientEph = peerEphPub;
                serverEph = MyEphemeralPub!;
            }

            // ProtocolHelpers sınıfını kullanıyoruz
            TranscriptHash = ProtocolHelpers.CalculateCanonicalTranscriptHash(
                clientID, serverID, clientEph, serverEph
            );

            // 3. Anahtarları Türet (Shared Secret + Transcript Hash)
            var keys = KeySchedule.DeriveSessionKeys(sharedSecret, TranscriptHash);

            // 4. Güvenli Kanalı Kur
            Channel = new SecureChannel(keys.Key, keys.NonceBase);
        }
    }
}
