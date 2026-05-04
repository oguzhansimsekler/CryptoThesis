using CryptoLibrary;
using System.Diagnostics;
using System.Security.Cryptography;

const int warmupIterations = 50;
const int measurementIterations = 1000;

// Pre-generate fixed keys/data used across benchmarks to isolate the measured operation
var ed25519Identity = IdentityService.GenerateLongTermIdentity();
var ed25519PublicKey = ed25519Identity.GetPublicKey();
var verifierIdentity = new IdentityService(ed25519PublicKey);
byte[] sampleData32 = RandomNumberGenerator.GetBytes(32);
byte[] sampleSignature = ed25519Identity.SignData(sampleData32);

var handshakeA = new HandshakeService();
var handshakeB = new HandshakeService();
byte[] pubB = handshakeB.GetPublicKey();

var results = new List<MeasurementResult>();

// ── Elliptic-Curve Key Agreement ──────────────────────────────────────────────
results.Add(Measure("X25519 Key Generation", warmupIterations, measurementIterations, () =>
{
    _ = new HandshakeService();
}));

results.Add(Measure("X25519 ECDH (Shared Secret)", warmupIterations, measurementIterations, () =>
{
    handshakeA.DeriveSharedSecret(pubB);
}));

// ── Ed25519 Identity Operations ───────────────────────────────────────────────
results.Add(Measure("Ed25519 Key Generation", warmupIterations, measurementIterations, () =>
{
    _ = IdentityService.GenerateLongTermIdentity();
}));

results.Add(Measure("Ed25519 Sign", warmupIterations, measurementIterations, () =>
{
    ed25519Identity.SignData(sampleData32);
}));

results.Add(Measure("Ed25519 Verify", warmupIterations, measurementIterations, () =>
{
    verifierIdentity.VerifySignature(sampleData32, sampleSignature);
}));

// ── Key Derivation ────────────────────────────────────────────────────────────
results.Add(Measure("SHA-256 Transcript Hash", warmupIterations, measurementIterations, () =>
{
    _ = SHA256.HashData(sampleData32);
}));

results.Add(Measure("HKDF Key Derivation", warmupIterations, measurementIterations, () =>
{
    byte[] sharedSecret = RandomNumberGenerator.GetBytes(32);
    byte[] transcriptHash = RandomNumberGenerator.GetBytes(32);
    _ = KeySchedule.DeriveSessionKeys(sharedSecret, transcriptHash);
}));

// ── AES-256-GCM Encryption ────────────────────────────────────────────────────
foreach (int size in new[] { 1024, 4096, 16384, 65536, 262144 })
{
    int capturedSize = size;
    string label = FormatBytes(size);
    results.Add(Measure($"AES-256-GCM Encrypt ({label})", warmupIterations, measurementIterations, () =>
    {
        var channel = CreateChannelPair().Sender;
        channel.Encrypt(CreatePayload(capturedSize));
    }));
}

// ── AES-256-GCM Decryption ────────────────────────────────────────────────────
foreach (int size in new[] { 1024, 4096, 16384, 65536, 262144 })
{
    int capturedSize = size;
    string label = FormatBytes(size);
    results.Add(Measure($"AES-256-GCM Decrypt ({label})", warmupIterations, measurementIterations, () =>
    {
        var channels = CreateChannelPair();
        SecurePackage pkg = channels.Sender.Encrypt(CreatePayload(capturedSize));
        channels.Receiver.Decrypt(pkg);
    }));
}

// ── Full Handshake ────────────────────────────────────────────────────────────
results.Add(Measure("Complete Secure Handshake", warmupIterations, measurementIterations, () =>
{
    var serverIdentity = IdentityService.CreateFromPrivateSeed(
        Convert.FromHexString("1E99423A4ED27608A15A2616DE1B5B3F4A8E7D3C2B1A09182736455463728190"));
    var clientIdentity = new IdentityService(ProtocolIdentity.GetPinnedServerPublicKey());
    var clientSession = new CryptoProtocolSession(clientIdentity, "Client");
    var serverSession = new CryptoProtocolSession(serverIdentity, "Server");
    byte[] clientNonce = RandomNumberGenerator.GetBytes(16);
    byte[] serverNonce = RandomNumberGenerator.GetBytes(16);

    serverSession.FinalizeHandshake(Array.Empty<byte>(), clientSession.MyEphemeralPub!, clientNonce, serverNonce);
    clientSession.FinalizeHandshake(serverIdentity.GetPublicKey(), serverSession.MyEphemeralPub!, clientNonce, serverNonce);
}));

// ── Output ────────────────────────────────────────────────────────────────────
Console.WriteLine("CryptoThesis Measurement Report");
Console.WriteLine($"Warmup iterations : {warmupIterations}");
Console.WriteLine($"Measure iterations: {measurementIterations}");
Console.WriteLine();

Console.WriteLine("| Operation | Average (ms) | Median (ms) | Min (ms) | Max (ms) |");
Console.WriteLine("|---|---:|---:|---:|---:|");
foreach (MeasurementResult result in results)
    Console.WriteLine($"| {result.Operation} | {result.AverageMs:F4} | {result.MedianMs:F4} | {result.MinMs:F4} | {result.MaxMs:F4} |");

Console.WriteLine();
Console.WriteLine("CSV");
Console.WriteLine("Operation,AverageMs,MedianMs,MinMs,MaxMs");
foreach (MeasurementResult result in results)
    Console.WriteLine($"{result.Operation},{result.AverageMs:F4},{result.MedianMs:F4},{result.MinMs:F4},{result.MaxMs:F4}");

// ── Helpers ───────────────────────────────────────────────────────────────────
static MeasurementResult Measure(string operation, int warmupCount, int measurementCount, Action action)
{
    for (int i = 0; i < warmupCount; i++)
        action();

    var samples = new double[measurementCount];
    for (int i = 0; i < measurementCount; i++)
    {
        long start = Stopwatch.GetTimestamp();
        action();
        long end = Stopwatch.GetTimestamp();
        samples[i] = (end - start) * 1000d / Stopwatch.Frequency;
    }

    Array.Sort(samples);

    return new MeasurementResult(
        operation,
        AverageMs: samples.Average(),
        MedianMs: Median(samples),
        MinMs: samples.First(),
        MaxMs: samples.Last());
}

static double Median(double[] sortedSamples)
{
    int middle = sortedSamples.Length / 2;
    return sortedSamples.Length % 2 == 0
        ? (sortedSamples[middle - 1] + sortedSamples[middle]) / 2d
        : sortedSamples[middle];
}

static (SecureChannel Sender, SecureChannel Receiver) CreateChannelPair()
{
    byte[] key = RandomNumberGenerator.GetBytes(32);
    byte[] nonce = RandomNumberGenerator.GetBytes(12);
    return (new SecureChannel(key, nonce), new SecureChannel(key, nonce));
}

static string CreatePayload(int sizeBytes) => new string('A', sizeBytes);

static string FormatBytes(int bytes) => bytes switch
{
    < 1024 => $"{bytes} B",
    < 1048576 => $"{bytes / 1024} KB",
    _ => $"{bytes / 1048576} MB"
};

internal record MeasurementResult(
    string Operation,
    double AverageMs,
    double MedianMs,
    double MinMs,
    double MaxMs);
