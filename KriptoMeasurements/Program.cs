using CryptoLibrary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

const int warmupIterations = 50;
const int measurementIterations = 1000;
const string demoServerSeedHex = "1E99423A4ED27608A15A2616DE1B5B3F4A8E7D3C2B1A09182736455463728190";

string outputPath = Path.GetFullPath(Path.Combine(
    AppContext.BaseDirectory,
    "..", "..", "..", "..",
    "KriptoClient", "wwwroot", "sample-data", "measurements.json"));

// Pre-generate fixed data to isolate the measured cryptographic operation.
var ed25519Identity = IdentityService.GenerateLongTermIdentity();
var ed25519PublicKey = ed25519Identity.GetPublicKey();
var verifierIdentity = new IdentityService(ed25519PublicKey);
byte[] sampleData32 = RandomNumberGenerator.GetBytes(32);
byte[] sampleSignature = ed25519Identity.SignData(sampleData32);

var handshakeA = new HandshakeService();
var handshakeB = new HandshakeService();
byte[] pubB = handshakeB.GetPublicKey();
byte[] hkdfSharedSecret = RandomNumberGenerator.GetBytes(32);
byte[] hkdfTranscriptHash = RandomNumberGenerator.GetBytes(32);
byte[] transcriptPayload = RandomNumberGenerator.GetBytes(160);

var results = new List<MeasurementResult>();

results.Add(Measure(
    "X25519 Key Generation",
    "Fresh ephemeral X25519 key-pair generation",
    warmupIterations,
    measurementIterations,
    () => _ = new HandshakeService()));

results.Add(Measure(
    "X25519 ECDH (Shared Secret)",
    "Shared-secret derivation against a fixed peer key",
    warmupIterations,
    measurementIterations,
    () => handshakeA.DeriveSharedSecret(pubB)));

results.Add(Measure(
    "Ed25519 Key Generation",
    "Long-term identity seed and public key generation",
    warmupIterations,
    measurementIterations,
    () => _ = IdentityService.GenerateLongTermIdentity()));

results.Add(Measure(
    "Ed25519 Sign",
    "Signature generation over a fixed 32-byte transcript fragment",
    warmupIterations,
    measurementIterations,
    () => ed25519Identity.SignData(sampleData32)));

results.Add(Measure(
    "Ed25519 Verify",
    "Signature verification using the pinned public key",
    warmupIterations,
    measurementIterations,
    () => verifierIdentity.VerifySignature(sampleData32, sampleSignature)));

results.Add(Measure(
    "SHA-256 Transcript Hash",
    "Digest over a fixed transcript-sized payload",
    warmupIterations,
    measurementIterations,
    () => _ = SHA256.HashData(transcriptPayload)));

results.Add(Measure(
    "HKDF Key Derivation",
    "Transcript-bound session key derivation from fixed inputs",
    warmupIterations,
    measurementIterations,
    () => _ = KeySchedule.DeriveSessionKeys(hkdfSharedSecret, hkdfTranscriptHash)));

foreach (int size in new[] { 1024, 4096, 16384, 65536, 262144 })
{
    string payload = CreatePayload(size);
    string label = FormatBytes(size);
    var senderChannel = CreateChannelPair().Sender;

    results.Add(Measure(
        $"AES-256-GCM Encrypt ({label})",
        $"{label} payload encryption on a persistent sender channel",
        warmupIterations,
        measurementIterations,
        () => senderChannel.Encrypt(payload)));
}

foreach (int size in new[] { 1024, 4096, 16384, 65536, 262144 })
{
    string payload = CreatePayload(size);
    string label = FormatBytes(size);
    byte[] key = RandomNumberGenerator.GetBytes(32);
    byte[] nonceBase = RandomNumberGenerator.GetBytes(12);
    var packageProducer = new SecureChannel(key, nonceBase);
    SecurePackage package = packageProducer.Encrypt(payload);

    results.Add(Measure(
        $"AES-256-GCM Decrypt ({label})",
        $"{label} payload decryption against a pre-encrypted package",
        warmupIterations,
        measurementIterations,
        () =>
        {
            var receiver = new SecureChannel(key, nonceBase);
            receiver.Decrypt(package);
        }));
}

results.Add(Measure(
    "Complete Secure Handshake",
    "ClientHello + ServerHello + transcript signing/verification + HKDF",
    warmupIterations,
    measurementIterations,
    () =>
    {
        var serverIdentity = IdentityService.CreateFromPrivateSeed(
            Convert.FromHexString(demoServerSeedHex));
        var clientIdentity = new IdentityService(ProtocolIdentity.GetPinnedServerPublicKey());
        var clientSession = new CryptoProtocolSession(clientIdentity, "Client");
        var serverSession = new CryptoProtocolSession(serverIdentity, "Server");
        byte[] clientNonce = RandomNumberGenerator.GetBytes(16);
        byte[] serverNonce = RandomNumberGenerator.GetBytes(16);

        serverSession.FinalizeHandshake(Array.Empty<byte>(), clientSession.MyEphemeralPub!, clientNonce, serverNonce);

        byte[] serverIdentityPublicKey = serverIdentity.GetPublicKey();
        byte[] transcript = ProtocolHelpers.BuildHandshakeTranscript(
            clientNonce,
            serverNonce,
            clientSession.MyEphemeralPub!,
            serverSession.MyEphemeralPub!,
            serverIdentityPublicKey);
        byte[] signature = serverIdentity.SignData(transcript);

        if (!clientIdentity.VerifySignature(transcript, signature))
            throw new InvalidOperationException("Handshake benchmark signature verification failed.");

        clientSession.FinalizeHandshake(
            serverIdentityPublicKey,
            serverSession.MyEphemeralPub!,
            clientNonce,
            serverNonce);
    }));

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
Console.WriteLine("Operation,AverageMs,MedianMs,MinMs,MaxMs,Notes");
foreach (MeasurementResult result in results)
    Console.WriteLine($"{result.Operation},{result.AverageMs:F4},{result.MedianMs:F4},{result.MinMs:F4},{result.MaxMs:F4},\"{result.Notes}\"");

Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
string payloadJson = JsonSerializer.Serialize(
    new MeasurementReport(
        WarmupIterations: warmupIterations,
        MeasurementIterations: measurementIterations,
        GeneratedAtUtc: DateTime.UtcNow,
        Results: results),
    new JsonSerializerOptions { WriteIndented = true });
File.WriteAllText(outputPath, payloadJson);

Console.WriteLine();
Console.WriteLine($"JSON output written to: {outputPath}");

static MeasurementResult Measure(
    string operation,
    string notes,
    int warmupCount,
    int measurementCount,
    Action action)
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
        notes,
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
    string Notes,
    double AverageMs,
    double MedianMs,
    double MinMs,
    double MaxMs);

internal record MeasurementReport(
    int WarmupIterations,
    int MeasurementIterations,
    DateTime GeneratedAtUtc,
    IReadOnlyList<MeasurementResult> Results);
