using CryptoLibrary;
using System.Diagnostics;
using System.Security.Cryptography;

const int warmupIterations = 50;
const int measurementIterations = 1000;
const int payloadSizeBytes = 1024;

var results = new List<MeasurementResult>
{
    Measure("X25519 Key Generation", warmupIterations, measurementIterations, () =>
    {
        _ = new HandshakeService();
    }),
    Measure("HKDF Key Derivation", warmupIterations, measurementIterations, () =>
    {
        byte[] sharedSecret = RandomNumberGenerator.GetBytes(32);
        byte[] transcriptHash = RandomNumberGenerator.GetBytes(32);
        _ = KeySchedule.DeriveSessionKeys(sharedSecret, transcriptHash);
    }),
    Measure("AES-256-GCM Encryption (1 KB)", warmupIterations, measurementIterations, () =>
    {
        var channel = CreateChannelPair().Sender;
        channel.Encrypt(CreatePayload(payloadSizeBytes));
    }),
    Measure("AES-256-GCM Decryption (1 KB)", warmupIterations, measurementIterations, () =>
    {
        var channels = CreateChannelPair();
        var channel = channels.Sender;
        var peerChannel = channels.Receiver;
        string payload = CreatePayload(payloadSizeBytes);
        SecurePackage package = channel.Encrypt(payload);
        peerChannel.Decrypt(package);
    }),
    Measure("Complete Secure Handshake", warmupIterations, measurementIterations, () =>
    {
        var serverIdentity = ProtocolIdentity.CreateServerIdentity();
        var clientIdentity = new IdentityService(ProtocolIdentity.GetPinnedServerPublicKey());
        var clientSession = new CryptoProtocolSession(clientIdentity, "Client");
        var serverSession = new CryptoProtocolSession(serverIdentity, "Server");
        byte[] clientNonce = RandomNumberGenerator.GetBytes(16);
        byte[] serverNonce = RandomNumberGenerator.GetBytes(16);

        serverSession.FinalizeHandshake(Array.Empty<byte>(), clientSession.MyEphemeralPub!, clientNonce, serverNonce);
        clientSession.FinalizeHandshake(serverIdentity.GetPublicKey(), serverSession.MyEphemeralPub!, clientNonce, serverNonce);
    })
};

Console.WriteLine("CryptoThesis Measurement Report");
Console.WriteLine($"Warmup iterations : {warmupIterations}");
Console.WriteLine($"Measure iterations: {measurementIterations}");
Console.WriteLine();

Console.WriteLine("| Operation | Average (ms) | Median (ms) | Min (ms) | Max (ms) |");
Console.WriteLine("|---|---:|---:|---:|---:|");
foreach (MeasurementResult result in results)
{
    Console.WriteLine($"| {result.Operation} | {result.AverageMs:F4} | {result.MedianMs:F4} | {result.MinMs:F4} | {result.MaxMs:F4} |");
}

Console.WriteLine();
Console.WriteLine("CSV");
Console.WriteLine("Operation,AverageMs,MedianMs,MinMs,MaxMs");
foreach (MeasurementResult result in results)
{
    Console.WriteLine($"{result.Operation},{result.AverageMs:F4},{result.MedianMs:F4},{result.MinMs:F4},{result.MaxMs:F4}");
}

static MeasurementResult Measure(string operation, int warmupCount, int measurementCount, Action action)
{
    for (int i = 0; i < warmupCount; i++)
    {
        action();
    }

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
    if (sortedSamples.Length % 2 == 0)
    {
        return (sortedSamples[middle - 1] + sortedSamples[middle]) / 2d;
    }

    return sortedSamples[middle];
}

static (SecureChannel Sender, SecureChannel Receiver) CreateChannelPair()
{
    byte[] key = RandomNumberGenerator.GetBytes(32);
    byte[] nonce = RandomNumberGenerator.GetBytes(12);
    return (new SecureChannel(key, nonce), new SecureChannel(key, nonce));
}

static string CreatePayload(int sizeBytes)
{
    return new string('A', sizeBytes);
}

internal record MeasurementResult(
    string Operation,
    double AverageMs,
    double MedianMs,
    double MinMs,
    double MaxMs);
