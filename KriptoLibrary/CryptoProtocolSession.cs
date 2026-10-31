namespace CryptoLibrary
{
    using System;

    public class CryptoProtocolSession
    {
        public string Role { get; }
        public IdentityService Identity { get; }
        public HandshakeService Handshake { get; }

        // Only the client generates an ML-KEM key pair; the server encapsulates to it.
        public KemService? Kem { get; }

        public SecureChannel? SendChannel { get; private set; }
        public SecureChannel? ReceiveChannel { get; private set; }

        public byte[]? MyEphemeralPub { get; }
        public byte[]? MyKemEncapsulationKey => Kem?.EncapsulationKey;
        public byte[]? PeerEphemeralPub { get; private set; }
        public byte[]? TranscriptHash { get; private set; }

        // True once the peer's Finished message has been verified.
        public bool IsConfirmed { get; private set; }

        private KeySchedule.SessionKeyMaterial? _keys;
        private byte[]? _signature;
        private byte[]? _serverFinished;

        public CryptoProtocolSession(IdentityService identity, string role)
        {
            Role = role;
            Identity = identity;
            Handshake = new HandshakeService();
            MyEphemeralPub = Handshake.GetPublicKey();
            if (role == "Client")
                Kem = new KemService();
        }

        /// <summary>Server side: derives the keys and returns the ML-KEM ciphertext for the ServerHello.</summary>
        public byte[] FinalizeAsServer(byte[] clientEph, byte[] clientKemKey, byte[] clientNonce, byte[] serverNonce)
        {
            EnsureRole("Server");
            var (kemCiphertext, kemSecret) = KemService.Encapsulate(clientKemKey);
            byte[] ecdhSecret = Handshake.DeriveSharedSecret(clientEph);

            TranscriptHash = ProtocolHelpers.CalculateCanonicalTranscriptHash(
                ProtocolHelpers.GetAnonymousIdentityPlaceholder(), Identity.GetPublicKey(),
                clientEph, MyEphemeralPub!, clientKemKey, kemCiphertext, clientNonce, serverNonce);

            PeerEphemeralPub = clientEph;
            InstallKeys(Concat(ecdhSecret, kemSecret));
            return kemCiphertext;
        }

        /// <summary>Client side: derives the keys from the ServerHello values.</summary>
        public void FinalizeAsClient(byte[] serverIdentityPub, byte[] serverEph, byte[] kemCiphertext,
            byte[] clientNonce, byte[] serverNonce)
        {
            EnsureRole("Client");
            byte[] ecdhSecret = Handshake.DeriveSharedSecret(serverEph);
            byte[] kemSecret = Kem!.Decapsulate(kemCiphertext);

            TranscriptHash = ProtocolHelpers.CalculateCanonicalTranscriptHash(
                ProtocolHelpers.GetAnonymousIdentityPlaceholder(), serverIdentityPub,
                MyEphemeralPub!, serverEph, Kem.EncapsulationKey, kemCiphertext, clientNonce, serverNonce);

            PeerEphemeralPub = serverEph;
            InstallKeys(Concat(ecdhSecret, kemSecret));
        }

        /// <summary>Server side: Finished value for the ServerHello, bound to the signature.</summary>
        public byte[] CreateServerFinished(byte[] signature)
        {
            EnsureRole("Server");
            _signature = signature;
            _serverFinished = ProtocolHelpers.ComputeServerFinished(Keys.ServerFinishedKey, TranscriptHash!, signature);
            return _serverFinished;
        }

        /// <summary>Client side: checks the server's Finished; on success the client may send data.</summary>
        public bool VerifyServerFinished(byte[] signature, byte[] serverFinished)
        {
            EnsureRole("Client");
            byte[] expected = ProtocolHelpers.ComputeServerFinished(Keys.ServerFinishedKey, TranscriptHash!, signature);
            if (!ProtocolHelpers.FixedTimeEquals(expected, serverFinished))
                return false;

            _signature = signature;
            _serverFinished = serverFinished;
            IsConfirmed = true;
            return true;
        }

        public byte[] CreateClientFinished()
        {
            EnsureRole("Client");
            if (!IsConfirmed)
                throw new InvalidOperationException("ServerFinished has not been verified.");
            return ProtocolHelpers.ComputeClientFinished(Keys.ClientFinishedKey, TranscriptHash!, _signature!, _serverFinished!);
        }

        /// <summary>Server side: checks the client's Finished; records are accepted only after this succeeds.</summary>
        public bool VerifyClientFinished(byte[] clientFinished)
        {
            EnsureRole("Server");
            byte[] expected = ProtocolHelpers.ComputeClientFinished(Keys.ClientFinishedKey, TranscriptHash!, _signature!, _serverFinished!);
            if (!ProtocolHelpers.FixedTimeEquals(expected, clientFinished))
                return false;

            IsConfirmed = true;
            return true;
        }

        private KeySchedule.SessionKeyMaterial Keys =>
            _keys ?? throw new InvalidOperationException("Handshake has not been finalized.");

        private void InstallKeys(byte[] inputKeyingMaterial)
        {
            _keys = KeySchedule.DeriveSessionKeys(inputKeyingMaterial, TranscriptHash!);
            bool isClient = Role == "Client";

            // The client sends with the client-to-server key; the server does the opposite.
            SendChannel = new SecureChannel(
                isClient ? _keys.ClientToServerKey : _keys.ServerToClientKey,
                isClient ? _keys.ClientToServerNonce : _keys.ServerToClientNonce);
            ReceiveChannel = new SecureChannel(
                isClient ? _keys.ServerToClientKey : _keys.ClientToServerKey,
                isClient ? _keys.ServerToClientNonce : _keys.ClientToServerNonce);
        }

        private void EnsureRole(string role)
        {
            if (Role != role)
                throw new InvalidOperationException($"This operation is only valid for the {role} role.");
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            return result;
        }
    }
}
