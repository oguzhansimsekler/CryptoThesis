namespace CryptoLibrary
{
    using System;

    public enum ServerHelloVerificationResult
    {
        Accepted,
        PinnedKeyMismatch,
        InvalidSignature,
        InvalidKeyMaterial,
        InvalidServerFinished
    }

    /// <summary>
    /// Client-side processing of a ServerHello: the identity key must equal the pinned key, the
    /// signature must verify over a transcript built from the client's own nonce and keys, the
    /// key exchange must succeed, and the server's Finished must match the derived keys.
    /// </summary>
    public static class ServerHelloVerifier
    {
        public static ServerHelloVerificationResult Verify(
            byte[] pinnedServerPublicKey,
            byte[] clientNonce,
            byte[] clientEphemeralPublicKey,
            byte[] clientKemEncapsulationKey,
            ServerHelloMessage hello)
        {
            if (!pinnedServerPublicKey.AsSpan().SequenceEqual(hello.ServerIdentityPublicKey))
                return ServerHelloVerificationResult.PinnedKeyMismatch;

            byte[] transcript = ProtocolHelpers.BuildHandshakeTranscript(
                clientNonce,
                hello.ServerNonce,
                clientEphemeralPublicKey,
                hello.ServerEphemeralPublicKey,
                clientKemEncapsulationKey,
                hello.KemCiphertext,
                hello.ServerIdentityPublicKey);

            var verifier = new IdentityService(pinnedServerPublicKey);
            return verifier.VerifySignature(transcript, hello.Signature)
                ? ServerHelloVerificationResult.Accepted
                : ServerHelloVerificationResult.InvalidSignature;
        }

        /// <summary>Runs every client check and, if all pass, leaves the session ready to send data.</summary>
        public static ServerHelloVerificationResult Complete(
            CryptoProtocolSession clientSession,
            byte[] pinnedServerPublicKey,
            byte[] clientNonce,
            ServerHelloMessage hello)
        {
            var result = Verify(pinnedServerPublicKey, clientNonce, clientSession.MyEphemeralPub!,
                clientSession.MyKemEncapsulationKey!, hello);
            if (result != ServerHelloVerificationResult.Accepted)
                return result;

            try
            {
                clientSession.FinalizeAsClient(hello.ServerIdentityPublicKey, hello.ServerEphemeralPublicKey,
                    hello.KemCiphertext, clientNonce, hello.ServerNonce);
            }
            catch (Exception)
            {
                return ServerHelloVerificationResult.InvalidKeyMaterial;
            }

            return clientSession.VerifyServerFinished(hello.Signature, hello.ServerFinished)
                ? ServerHelloVerificationResult.Accepted
                : ServerHelloVerificationResult.InvalidServerFinished;
        }
    }
}
