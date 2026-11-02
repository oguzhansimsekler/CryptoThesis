using CryptoLibrary;
using Org.BouncyCastle.Crypto.Digests;
using System.Diagnostics;
using System.Security.Cryptography;

namespace KriptoBenchmarks;

public sealed record BenchmarkCase(string Operation, string Notes, Action Action);

public sealed record BenchmarkOptions(
    double WarmupMs = 1000,
    int MinWarmupOps = 5,
    double TargetBatchMs = 25,
    int Batches = 30);

/// <summary>
/// Latency of one operation summarised over batches. Each batch runs the operation
/// OpsPerBatch times and yields one sample: batch time divided by the number of runs.
/// </summary>
public sealed record BenchmarkResult(
    string Operation,
    string Notes,
    int OpsPerBatch,
    int Batches,
    double MeanMs,
    double MedianMs,
    double P95Ms,
    double MinMs,
    double MaxMs,
    double StdDevMs);

public sealed record BenchmarkReport(
    string Environment,
    string Runtime,
    string Methodology,
    DateTime GeneratedAtUtc,
    BenchmarkOptions Options,
    IReadOnlyList<BenchmarkResult> Results);

/// <summary>
/// Benchmark suite run unchanged on native .NET (KriptoMeasurements) and in the browser
/// (KriptoClient). Browsers coarsen performance.now() (0.1 ms in Chrome, 1 ms in
/// Firefox), so batches are timed instead of single operations.
/// </summary>
public static class BenchmarkSuite
{
    public const string Methodology =
        "Batched timing: after a time-based warm-up, each batch runs the operation enough times to last " +
        "about TargetBatchMs; the per-operation latency of a batch is its elapsed time divided by the number " +
        "of operations. Statistics, including the 95th percentile, are computed over the per-batch values.";

    // Same demo seed as in ProtocolIdentity; not a secret.
    private const string DemoServerSeedHex = "1E99423A4ED27608A15A2616DE1B5B3F4A8E7D3C2B1A09182736455463728190";

    public static readonly int[] PayloadSizes = { 1024, 4096, 16384, 65536, 262144 };

    public static IReadOnlyList<BenchmarkCase> CreateCases()
    {
        var cases = new List<BenchmarkCase>();

        var ed25519Identity = IdentityService.GenerateLongTermIdentity();
        var verifierIdentity = new IdentityService(ed25519Identity.GetPublicKey());
        byte[] sampleData32 = RandomNumberGenerator.GetBytes(32);
        byte[] sampleSignature = ed25519Identity.SignData(sampleData32);
        var handshakeA = new HandshakeService();
        byte[] pubB = new HandshakeService().GetPublicKey();
        var kem = new KemService();
        var (kemCiphertext, _) = KemService.Encapsulate(kem.EncapsulationKey);
        byte[] ikm = RandomNumberGenerator.GetBytes(64);
        byte[] transcriptHash = RandomNumberGenerator.GetBytes(32);
        byte[] transcriptPayload = RandomNumberGenerator.GetBytes(160);
        byte[] finishedKey = RandomNumberGenerator.GetBytes(32);
        byte[] signature64 = RandomNumberGenerator.GetBytes(64);
        var serverIdentity = IdentityService.CreateFromPrivateSeed(Convert.FromHexString(DemoServerSeedHex));

        cases.Add(new("X25519 Key Generation", "Fresh ephemeral X25519 key-pair generation",
            () => _ = new HandshakeService()));
        cases.Add(new("X25519 ECDH (Shared Secret)", "Shared-secret derivation against a fixed peer key",
            () => handshakeA.DeriveSharedSecret(pubB)));
        cases.Add(new("ML-KEM-768 Key Generation", "Client key pair for the post-quantum half",
            () => _ = new KemService()));
        cases.Add(new("ML-KEM-768 Encapsulation", "Server side, against a fixed encapsulation key",
            () => KemService.Encapsulate(kem.EncapsulationKey)));
        cases.Add(new("ML-KEM-768 Decapsulation", "Client side, against a fixed ciphertext",
            () => kem.Decapsulate(kemCiphertext)));
        cases.Add(new("Ed25519 Sign", "Signature over a fixed 32-byte transcript fragment",
            () => ed25519Identity.SignData(sampleData32)));
        cases.Add(new("Ed25519 Verify", "Verification using the pinned public key",
            () => verifierIdentity.VerifySignature(sampleData32, sampleSignature)));
        cases.Add(new("SHA-256 Transcript Hash", "BouncyCastle SHA-256 over a transcript-sized payload",
            () =>
            {
                var digest = new Sha256Digest();
                digest.BlockUpdate(transcriptPayload, 0, transcriptPayload.Length);
                digest.DoFinal(new byte[32], 0);
            }));
        cases.Add(new("HKDF Key Derivation", "152 bytes of session keys from a 64-byte hybrid secret",
            () => _ = KeySchedule.DeriveSessionKeys(ikm, transcriptHash)));
        cases.Add(new("Finished MAC", "HMAC-SHA256 over the transcript hash and signature",
            () => ProtocolHelpers.ComputeServerFinished(finishedKey, transcriptHash, signature64)));

        foreach (int size in PayloadSizes)
        {
            byte[] payload = RandomNumberGenerator.GetBytes(size);
            var sender = new SecureChannel(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(12));
            cases.Add(new($"AES-256-GCM Encrypt ({FormatBytes(size)})",
                $"{FormatBytes(size)} payload encryption on a persistent sender channel",
                () => sender.Encrypt(payload)));
        }

        foreach (int size in PayloadSizes)
        {
            cases.Add(new($"AES-256-GCM Decrypt ({FormatBytes(size)})",
                $"{FormatBytes(size)} payload decryption, including tag verification, on a persistent receiver channel",
                CreateDecryptionLoop(size)));
        }

        cases.Add(new("Complete Handshake (classical)",
            "X25519 only: both sides, signature, client checks, HKDF, both Finished messages",
            () => RunClassicalHandshake(serverIdentity)));
        cases.Add(new("Complete Handshake (hybrid)",
            "X25519 + ML-KEM-768 as deployed: both sides, signature, client checks, HKDF, both Finished messages",
            () => RunHybridHandshake(serverIdentity)));

        return cases;
    }

    public static BenchmarkResult Run(BenchmarkCase benchmark, BenchmarkOptions options)
    {
        int warmupOps = 0;
        long warmupStart = Stopwatch.GetTimestamp();
        while (warmupOps < options.MinWarmupOps || ElapsedMs(warmupStart) < options.WarmupMs)
        {
            benchmark.Action();
            warmupOps++;
        }

        // The batch size comes from the last stretch of the warm-up only. The early iterations
        // still run unoptimised code and would make the batches far too short.
        int calibrationOps = 0;
        long calibrationStart = Stopwatch.GetTimestamp();
        while (calibrationOps < options.MinWarmupOps || ElapsedMs(calibrationStart) < options.TargetBatchMs)
        {
            benchmark.Action();
            calibrationOps++;
        }
        double estimateMs = ElapsedMs(calibrationStart) / calibrationOps;
        int opsPerBatch = Math.Max(1, (int)Math.Ceiling(options.TargetBatchMs / Math.Max(estimateMs, 1e-6)));

        var samples = new double[options.Batches];
        for (int b = 0; b < options.Batches; b++)
        {
            long start = Stopwatch.GetTimestamp();
            for (int i = 0; i < opsPerBatch; i++)
                benchmark.Action();
            samples[b] = ElapsedMs(start) / opsPerBatch;
        }

        Array.Sort(samples);
        double mean = samples.Average();
        double variance = samples.Sum(s => (s - mean) * (s - mean)) / Math.Max(1, samples.Length - 1);

        return new BenchmarkResult(benchmark.Operation, benchmark.Notes, opsPerBatch, options.Batches,
            mean, Percentile(samples, 0.50), Percentile(samples, 0.95), samples[0], samples[^1], Math.Sqrt(variance));
    }

    // Linear interpolation between closest ranks on sorted data.
    private static double Percentile(double[] sorted, double p)
    {
        double rank = p * (sorted.Length - 1);
        int lower = (int)Math.Floor(rank);
        int upper = Math.Min(lower + 1, sorted.Length - 1);
        return sorted[lower] + (rank - lower) * (sorted[upper] - sorted[lower]);
    }

    public static void RunHybridHandshake(IdentityService serverIdentity)
    {
        byte[] pinned = ProtocolIdentity.GetPinnedServerPublicKey();
        var client = new CryptoProtocolSession(new IdentityService(pinned), "Client");
        var server = new CryptoProtocolSession(serverIdentity, "Server");
        byte[] clientNonce = RandomNumberGenerator.GetBytes(16);
        byte[] serverNonce = RandomNumberGenerator.GetBytes(16);

        byte[] kemCiphertext = server.FinalizeAsServer(client.MyEphemeralPub!, client.MyKemEncapsulationKey!, clientNonce, serverNonce);
        byte[] transcript = ProtocolHelpers.BuildHandshakeTranscript(clientNonce, serverNonce,
            client.MyEphemeralPub!, server.MyEphemeralPub!, client.MyKemEncapsulationKey!, kemCiphertext, pinned);
        byte[] signature = serverIdentity.SignData(transcript);
        var hello = new ServerHelloMessage
        {
            ServerNonce = serverNonce,
            ServerEphemeralPublicKey = server.MyEphemeralPub!,
            KemCiphertext = kemCiphertext,
            ServerIdentityPublicKey = pinned,
            Signature = signature,
            ServerFinished = server.CreateServerFinished(signature)
        };

        if (ServerHelloVerifier.Complete(client, pinned, clientNonce, hello) != ServerHelloVerificationResult.Accepted ||
            !server.VerifyClientFinished(client.CreateClientFinished()))
            throw new InvalidOperationException("Hybrid handshake benchmark failed.");
    }

    // The same handshake without the ML-KEM half, for comparison only; the protocol always runs hybrid.
    private static void RunClassicalHandshake(IdentityService serverIdentity)
    {
        byte[] pinned = ProtocolIdentity.GetPinnedServerPublicKey();
        byte[] none = Array.Empty<byte>();
        var clientEph = new HandshakeService();
        var serverEph = new HandshakeService();
        byte[] clientNonce = RandomNumberGenerator.GetBytes(16);
        byte[] serverNonce = RandomNumberGenerator.GetBytes(16);
        byte[] a = clientEph.GetPublicKey();
        byte[] b = serverEph.GetPublicKey();
        byte[] anonymous = ProtocolHelpers.GetAnonymousIdentityPlaceholder();

        // Server
        byte[] serverHash = ProtocolHelpers.CalculateCanonicalTranscriptHash(anonymous, pinned, a, b, none, none, clientNonce, serverNonce);
        var serverKeys = KeySchedule.DeriveSessionKeys(serverEph.DeriveSharedSecret(a), serverHash);
        byte[] signature = serverIdentity.SignData(ProtocolHelpers.BuildHandshakeTranscript(clientNonce, serverNonce, a, b, none, none, pinned));
        byte[] serverFinished = ProtocolHelpers.ComputeServerFinished(serverKeys.ServerFinishedKey, serverHash, signature);

        // Client
        var verifier = new IdentityService(pinned);
        if (!verifier.VerifySignature(ProtocolHelpers.BuildHandshakeTranscript(clientNonce, serverNonce, a, b, none, none, pinned), signature))
            throw new InvalidOperationException("Classical handshake benchmark failed.");
        byte[] clientHash = ProtocolHelpers.CalculateCanonicalTranscriptHash(anonymous, pinned, a, b, none, none, clientNonce, serverNonce);
        var clientKeys = KeySchedule.DeriveSessionKeys(clientEph.DeriveSharedSecret(b), clientHash);
        if (!ProtocolHelpers.FixedTimeEquals(serverFinished,
                ProtocolHelpers.ComputeServerFinished(clientKeys.ServerFinishedKey, clientHash, signature)))
            throw new InvalidOperationException("Classical handshake benchmark failed.");
        byte[] clientFinished = ProtocolHelpers.ComputeClientFinished(clientKeys.ClientFinishedKey, clientHash, signature, serverFinished);

        // Server checks the client's Finished.
        if (!ProtocolHelpers.FixedTimeEquals(clientFinished,
                ProtocolHelpers.ComputeClientFinished(serverKeys.ClientFinishedKey, serverHash, signature, serverFinished)))
            throw new InvalidOperationException("Classical handshake benchmark failed.");
    }

    private static double ElapsedMs(long startTimestamp) =>
        (Stopwatch.GetTimestamp() - startTimestamp) * 1000d / Stopwatch.Frequency;

    // The receiver accepts each record once and in order, so decryption runs through a ring of
    // records encrypted in advance; a new receiver is needed only when the ring is exhausted.
    // The ring holds about 256 KB, which fits in the cache as the single encryption input does.
    private static Action CreateDecryptionLoop(int size)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonceBase = RandomNumberGenerator.GetBytes(12);
        byte[] payload = RandomNumberGenerator.GetBytes(size);
        using var sender = new SecureChannel(key, nonceBase);
        SecurePackage[] ring = Enumerable.Range(0, Math.Max(2, (256 << 10) / size))
            .Select(_ => sender.Encrypt(payload)).ToArray();

        var receiver = new SecureChannel(key, nonceBase);
        int next = 0;
        return () =>
        {
            if (next == ring.Length)
            {
                receiver.Dispose();
                receiver = new SecureChannel(key, nonceBase);
                next = 0;
            }
            receiver.Decrypt(ring[next++]);
        };
    }

    private static string FormatBytes(int bytes) => bytes < 1024 ? $"{bytes} B" : $"{bytes / 1024} KB";
}
