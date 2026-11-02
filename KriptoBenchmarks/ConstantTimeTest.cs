using CryptoLibrary;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Diagnostics;
using System.Security.Cryptography;

namespace KriptoBenchmarks;

public sealed record ConstantTimeResult(
    string Operation,
    string Classes,
    int Samples,
    double MeanClass0Us,
    double MeanClass1Us,
    double TUncropped,
    double TCropped50,
    double TCropped90,
    double TCropped99,
    double MaxAbsT);

/// <summary>
/// Timing-leakage test in the style of dudect (Reparaz, Balasch and Verbauwhede, DATE 2017).
/// Each operation is run on inputs from two classes, chosen at random per call; the execution
/// times of the two classes are compared with Welch's t-test, on all samples and on samples
/// cropped at the 50th, 90th and 99th percentiles. |t| above 4.5 is taken as evidence of a
/// timing difference. Both classes draw their inputs from pools of 1024 distinct objects, so
/// they differ in content but not in memory layout. Only meaningful natively: browsers cannot
/// time single calls.
/// </summary>
public static class ConstantTimeTest
{
    public const double Threshold = 4.5;

    private sealed record Target(string Operation, string Classes, Func<int, Action> Prepare);

    public static IReadOnlyList<ConstantTimeResult> RunAll(int samples)
    {
        var results = new List<ConstantTimeResult>();
        foreach (Target target in CreateTargets())
            results.Add(Run(target, samples));
        return results;
    }

    private static IEnumerable<Target> CreateTargets()
    {
        // BouncyCastle X25519, which HandshakeService wraps, so that the fixed key can be copied.
        var peerPublic = new X25519PrivateKeyParameters(new SecureRandom()).GeneratePublicKey();
        byte[] fixedScalar = RandomNumberGenerator.GetBytes(32);
        var fixedKeys = Pool(() => new X25519PrivateKeyParameters(fixedScalar, 0));
        var randomKeys = Pool(() => new X25519PrivateKeyParameters(new SecureRandom()));
        yield return new("X25519 shared secret", "fixed vs random private key",
            cls =>
            {
                var k = cls == 0 ? Pick(fixedKeys) : Pick(randomKeys);
                return () => k.GenerateSecret(peerPublic, new byte[32], 0);
            });

        var signer = IdentityService.GenerateLongTermIdentity();
        byte[] fixedMessage = RandomNumberGenerator.GetBytes(32);
        var fixedMessages = Pool(() => (byte[])fixedMessage.Clone());
        var messages = Pool(() => RandomNumberGenerator.GetBytes(32));
        yield return new("Ed25519 sign", "fixed vs random 32-byte message",
            cls => { byte[] m = cls == 0 ? Pick(fixedMessages) : Pick(messages); return () => signer.SignData(m); });

        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonceBase = RandomNumberGenerator.GetBytes(12);
        byte[] fixedPlaintext = new byte[1024];
        var fixedPlaintexts = Pool(() => (byte[])fixedPlaintext.Clone());
        var randomPlaintexts = Pool(() => RandomNumberGenerator.GetBytes(1024));
        var sender = new SecureChannel(key, nonceBase);
        yield return new("Record encryption (1 KB)", "fixed vs random plaintext",
            cls =>
            {
                byte[] data = cls == 0 ? Pick(fixedPlaintexts) : Pick(randomPlaintexts);
                return () => sender.Encrypt(data);
            });

        // Not part of the record layer: an application that sends text encodes it first,
        // and the cost of UTF-8 encoding depends on the characters.
        var fixedTexts = Pool(() => new string('A', 1024));
        var texts = Pool(() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(768)));
        yield return new("UTF-8 encoding (1 KB), application side", "fixed vs random text",
            cls =>
            {
                string text = cls == 0 ? Pick(fixedTexts) : Pick(texts);
                return () => System.Text.Encoding.UTF8.GetBytes(text);
            });

        SecurePackage valid = new SecureChannel(key, nonceBase).Encrypt(fixedPlaintext);
        yield return new("AES-256-GCM tag check (1 KB)", "tag wrong in first byte vs in last byte",
            cls =>
            {
                var package = Clone(valid);
                package.Tag[cls == 0 ? 0 : 15] ^= 0x01;
                return () => { try { new SecureChannel(key, nonceBase).Decrypt(package); } catch (Exception) { } };
            });

        byte[] expected = RandomNumberGenerator.GetBytes(32);
        yield return new("Finished comparison", "mismatch in first byte vs in last byte",
            cls =>
            {
                byte[] received = (byte[])expected.Clone();
                received[cls == 0 ? 0 : 31] ^= 0x01;
                return () => ProtocolHelpers.FixedTimeEquals(expected, received);
            });

        var kem = new KemService();
        var (ciphertext, _) = KemService.Encapsulate(kem.EncapsulationKey);
        var unmodified = Pool(() => (byte[])ciphertext.Clone());
        var modified = Pool(() => { byte[] ct = (byte[])ciphertext.Clone(); ct[RandomNumberGenerator.GetInt32(ct.Length)] ^= 0x01; return ct; });
        yield return new("ML-KEM-768 decapsulation", "valid vs modified ciphertext",
            cls =>
            {
                byte[] ct = cls == 0 ? Pick(unmodified) : Pick(modified);
                return () => kem.Decapsulate(ct);
            });
    }

    // Random inputs are drawn from a pool built before timing.
    private static T[] Pool<T>(Func<T> create) => Enumerable.Range(0, 1024).Select(_ => create()).ToArray();

    private static T Pick<T>(T[] pool) => pool[RandomNumberGenerator.GetInt32(pool.Length)];

    private static ConstantTimeResult Run(Target target, int samples)
    {
        // Inputs and class labels are prepared before timing, as in dudect.
        var classes = new int[samples];
        var actions = new Action[samples];
        for (int i = 0; i < samples; i++)
        {
            classes[i] = RandomNumberGenerator.GetInt32(2);
            actions[i] = target.Prepare(classes[i]);
        }

        for (int i = 0; i < Math.Min(1000, samples); i++)
            actions[i]();

        GC.Collect();
        GC.WaitForPendingFinalizers();

        var ticks = new long[samples];
        for (int i = 0; i < samples; i++)
        {
            long start = Stopwatch.GetTimestamp();
            actions[i]();
            ticks[i] = Stopwatch.GetTimestamp() - start;
        }

        double toUs = 1_000_000d / Stopwatch.Frequency;
        double[] sorted = ticks.Select(t => (double)t).OrderBy(t => t).ToArray();

        double TFor(double percentile)
        {
            double limit = percentile >= 1 ? double.MaxValue : sorted[(int)(percentile * (sorted.Length - 1))];
            var c0 = new List<double>();
            var c1 = new List<double>();
            for (int i = 0; i < samples; i++)
            {
                if (ticks[i] > limit) continue;
                (classes[i] == 0 ? c0 : c1).Add(ticks[i]);
            }
            return WelchT(c0, c1);
        }

        double tAll = TFor(1), t50 = TFor(0.50), t90 = TFor(0.90), t99 = TFor(0.99);
        double mean0 = Enumerable.Range(0, samples).Where(i => classes[i] == 0).Average(i => ticks[i]) * toUs;
        double mean1 = Enumerable.Range(0, samples).Where(i => classes[i] == 1).Average(i => ticks[i]) * toUs;

        return new ConstantTimeResult(target.Operation, target.Classes, samples, mean0, mean1,
            tAll, t50, t90, t99, new[] { tAll, t50, t90, t99 }.Max(Math.Abs));
    }

    private static double WelchT(List<double> a, List<double> b)
    {
        if (a.Count < 2 || b.Count < 2) return 0;
        double ma = a.Average(), mb = b.Average();
        double va = a.Sum(x => (x - ma) * (x - ma)) / (a.Count - 1);
        double vb = b.Sum(x => (x - mb) * (x - mb)) / (b.Count - 1);
        double se = Math.Sqrt(va / a.Count + vb / b.Count);
        return se == 0 ? 0 : (ma - mb) / se;
    }

    private static SecurePackage Clone(SecurePackage p) => new()
    {
        SequenceNumber = p.SequenceNumber,
        Ciphertext = (byte[])p.Ciphertext.Clone(),
        Tag = (byte[])p.Tag.Clone()
    };
}
