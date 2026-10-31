namespace CryptoLibrary
{
    using System;

    public enum ServerHelloVerificationResult
    {
        Accepted,
        PinnedKeyMismatch,
        InvalidSignature
    }

    /// <summary>
    /// Client-side check of a ServerHello: the identity key must equal the pinned key, and the
    /// signature must verify over a transcript built from the client's own nonce and ephemeral key.
    /// </summary>
    public static class ServerHelloVerifier
    {
        public static ServerHelloVerificationResult Verify(
            byte[] pinnedServerPublicKey,
            byte[] clientNonce,
            byte[] clientEphemeralPublicKey,
            ServerHelloMessage hello)
        {
            if (!pinnedServerPublicKey.AsSpan().SequenceEqual(hello.ServerIdentityPublicKey))
                return ServerHelloVerificationResult.PinnedKeyMismatch;

            byte[] transcript = ProtocolHelpers.BuildHandshakeTranscript(
                clientNonce,
                hello.ServerNonce,
                clientEphemeralPublicKey,
                hello.ServerEphemeralPublicKey,
                hello.ServerIdentityPublicKey);

            var verifier = new IdentityService(pinnedServerPublicKey);
            return verifier.VerifySignature(transcript, hello.Signature)
                ? ServerHelloVerificationResult.Accepted
                : ServerHelloVerificationResult.InvalidSignature;
        }
    }
}
