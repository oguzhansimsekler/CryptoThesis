using CryptoLibrary;
using Org.BouncyCastle.Crypto.Digests;
using System.Diagnostics;
using System.Security.Cryptography;

namespace KriptoBenchmarks;

public sealed record BenchmarkCase(string Operation, string Notes, Action Action);

public sealed record BenchmarkOptions(
    double WarmupMs = 300,
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
        "of operations. Statistics are computed over the per-batch values.";

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
        byte[] hkdfSharedSecret = RandomNumberGenerator.GetBytes(32);
        byte[] hkdfTranscriptHash = RandomNumberGenerator.GetBytes(32);
        byte[] transcriptPayload = RandomNumberGenerator.GetBytes(160);

        cases.Add(new("X25519 Key Generation", "Fresh ephemeral X25519 key-pair generation",
            () => _ = new HandshakeService()));
        cases.Add(new("X25519 ECDH (Shared Secret)", "Shared-secret derivation against a fixed peer key",
            () => handshakeA.DeriveSharedSecret(pubB)));
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
        cases.Add(new("HKDF Key Derivation", "Transcript-bound session key derivation from fixed inputs",
            () => _ = KeySchedule.DeriveSessionKeys(hkdfSharedSecret, hkdfTranscriptHash)));

        foreach (int size in PayloadSizes)
        {
            string payload = new('A', size);
            var sender = new SecureChannel(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(12));
            cases.Add(new($"AES-256-GCM Encrypt ({FormatBytes(size)})",
                $"{FormatBytes(size)} payload encryption on a persistent sender channel",
                () => sender.Encrypt(payload)));
        }

        foreach (int size in PayloadSizes)
        {
            byte[] key = RandomNumberGenerator.GetBytes(32);
            byte[] nonceBase = RandomNumberGenerator.GetBytes(12);
            SecurePackage package = new SecureChannel(key, nonceBase).Encrypt(new string('A', size));
            cases.Add(new($"AES-256-GCM Decrypt ({FormatBytes(size)})",
                $"{FormatBytes(size)} payload decryption, including tag verification",
                () => new SecureChannel(key, nonceBase).Decrypt(package)));
        }

        cases.Add(new("Complete Secure Handshake",
            "ClientHello + ServerHello + transcript signing/verification + HKDF on both sides",
            RunHandshake));

        return cases;
    }

    public static BenchmarkResult Run(BenchmarkCase benchmark, BenchmarkOptions options)
    {
        // The warm-up also gives a rough cost estimate used to size the batches.
        int warmupOps = 0;
        long warmupStart = Stopwatch.GetTimestamp();
        while (warmupOps < options.MinWarmupOps || ElapsedMs(warmupStart) < options.WarmupMs)
        {
            benchmark.Action();
            warmupOps++;
        }
        double estimateMs = ElapsedMs(warmupStart) / warmupOps;
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
        int mid = samples.Length / 2;
        double median = samples.Length % 2 == 0 ? (samples[mid - 1] + samples[mid]) / 2 : samples[mid];

        return new BenchmarkResult(benchmark.Operation, benchmark.Notes, opsPerBatch, options.Batches,
            mean, median, samples[0], samples[^1], Math.Sqrt(variance));
    }

    private static void RunHandshake()
    {
        var serverIdentity = IdentityService.CreateFromPrivateSeed(Convert.FromHexString(DemoServerSeedHex));
        var clientSession = new CryptoProtocolSession(new IdentityService(ProtocolIdentity.GetPinnedServerPublicKey()), "Client");
        var serverSession = new CryptoProtocolSession(serverIdentity, "Server");
        byte[] clientNonce = RandomNumberGenerator.GetBytes(16);
        byte[] serverNonce = RandomNumberGenerator.GetBytes(16);

        serverSession.FinalizeHandshake(Array.Empty<byte>(), clientSession.MyEphemeralPub!, clientNonce, serverNonce);

        byte[] serverIdentityPublicKey = serverIdentity.GetPublicKey();
        byte[] transcript = ProtocolHelpers.BuildHandshakeTranscript(
            clientNonce, serverNonce, clientSession.MyEphemeralPub!, serverSession.MyEphemeralPub!, serverIdentityPublicKey);
        var hello = new ServerHelloMessage
        {
            ServerNonce = serverNonce,
            ServerEphemeralPublicKey = serverSession.MyEphemeralPub!,
            ServerIdentityPublicKey = serverIdentityPublicKey,
            Signature = serverIdentity.SignData(transcript)
        };

        if (ServerHelloVerifier.Verify(ProtocolIdentity.GetPinnedServerPublicKey(), clientNonce,
                clientSession.MyEphemeralPub!, hello) != ServerHelloVerificationResult.Accepted)
            throw new InvalidOperationException("Handshake benchmark verification failed.");

        clientSession.FinalizeHandshake(serverIdentityPublicKey, serverSession.MyEphemeralPub!, clientNonce, serverNonce);
    }

    private static double ElapsedMs(long startTimestamp) =>
        (Stopwatch.GetTimestamp() - startTimestamp) * 1000d / Stopwatch.Frequency;

    private static string FormatBytes(int bytes) => bytes < 1024 ? $"{bytes} B" : $"{bytes / 1024} KB";
}
