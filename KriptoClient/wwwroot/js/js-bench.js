// JavaScript baselines for the browser benchmark: the same operations as KriptoBenchmarks,
// implemented with the browser's Web Cryptography API and with the pure-JS noble libraries.
// Timing follows BenchmarkSuite: time-based warm-up, ~25 ms batches, 30 batches.
import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { gcm } from '@noble/ciphers/aes.js';

const OPTIONS = { WarmupMs: 300, MinWarmupOps: 5, TargetBatchMs: 25, Batches: 30 };
const PAYLOAD_SIZES = [1024, 4096, 16384, 65536, 262144];
const subtle = globalThis.crypto.subtle;
// getRandomValues fills at most 65536 bytes per call.
const rnd = n => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
    return out;
};

async function measure(op) {
    let warmupOps = 0;
    const warmupStart = performance.now();
    while (warmupOps < OPTIONS.MinWarmupOps || performance.now() - warmupStart < OPTIONS.WarmupMs) {
        await op();
        warmupOps++;
    }
    const estimate = (performance.now() - warmupStart) / warmupOps;
    const opsPerBatch = Math.max(1, Math.ceil(OPTIONS.TargetBatchMs / Math.max(estimate, 1e-6)));

    const samples = [];
    for (let b = 0; b < OPTIONS.Batches; b++) {
        const start = performance.now();
        for (let i = 0; i < opsPerBatch; i++) await op();
        samples.push((performance.now() - start) / opsPerBatch);
    }
    samples.sort((a, b) => a - b);
    const mean = samples.reduce((s, x) => s + x, 0) / samples.length;
    const sd = Math.sqrt(samples.reduce((s, x) => s + (x - mean) ** 2, 0) / (samples.length - 1));
    const pct = p => {
        const rank = p * (samples.length - 1), lo = Math.floor(rank), hi = Math.min(lo + 1, samples.length - 1);
        return samples[lo] + (rank - lo) * (samples[hi] - samples[lo]);
    };
    return { OpsPerBatch: opsPerBatch, Batches: OPTIONS.Batches, MeanMs: mean, MedianMs: pct(0.5), P95Ms: pct(0.95),
        MinMs: samples[0], MaxMs: samples[samples.length - 1], StdDevMs: sd };
}

function label(bytes) { return `${bytes / 1024} KB`; }

// Nonce derived from the counter, as in SecureChannel, so no random number generation is timed.
function nonce(seq) {
    const n = new Uint8Array(12);
    new DataView(n.buffer).setBigUint64(0, BigInt(seq));
    return n;
}

function aad(seq) {
    const a = new Uint8Array(8);
    new DataView(a.buffer).setBigUint64(0, BigInt(seq));
    return a;
}

// Each engine returns a list of [operation, notes, async op].
async function webCryptoCases() {
    const peer = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const mine = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    const signer = await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    const msg = rnd(32);
    const sig = await subtle.sign({ name: 'Ed25519' }, signer.privateKey, msg);
    const transcript = rnd(160), ikm = rnd(64), salt = rnd(32), info = rnd(36), finishedData = rnd(117);
    const hmacKey = await subtle.importKey('raw', rnd(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    const aesKey = await subtle.importKey('raw', rnd(32), 'AES-GCM', false, ['encrypt', 'decrypt']);

    const hkdfOp = async (input) => {
        const k = await subtle.importKey('raw', input, 'HKDF', false, ['deriveBits']);
        return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, 152 * 8));
    };

    const cases = [
        ['X25519 Key Generation', 'subtle.generateKey X25519', () => subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])],
        ['X25519 ECDH (Shared Secret)', 'subtle.deriveBits X25519', () => subtle.deriveBits({ name: 'X25519', public: peer.publicKey }, mine.privateKey, 256)],
        ['Ed25519 Sign', 'subtle.sign Ed25519', () => subtle.sign({ name: 'Ed25519' }, signer.privateKey, msg)],
        ['Ed25519 Verify', 'subtle.verify Ed25519', () => subtle.verify({ name: 'Ed25519' }, signer.publicKey, sig, msg)],
        ['SHA-256 Transcript Hash', 'subtle.digest over 160 bytes', () => subtle.digest('SHA-256', transcript)],
        ['HKDF Key Derivation', 'importKey + deriveBits, 152 bytes', () => hkdfOp(ikm)],
        ['Finished MAC', 'subtle.sign HMAC-SHA256', () => subtle.sign('HMAC', hmacKey, finishedData)],
    ];

    for (const size of PAYLOAD_SIZES) {
        const data = rnd(size);
        let seq = 0n;
        cases.push([`AES-256-GCM Encrypt (${label(size)})`, 'subtle.encrypt, pre-imported key', () => {
            seq++;
            return subtle.encrypt({ name: 'AES-GCM', iv: nonce(seq), additionalData: aad(seq), tagLength: 128 }, aesKey, data);
        }]);
    }
    for (const size of PAYLOAD_SIZES) {
        const iv = rnd(12), ad = aad(1);
        const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: ad, tagLength: 128 }, aesKey, rnd(size));
        cases.push([`AES-256-GCM Decrypt (${label(size)})`, 'subtle.decrypt including tag check', () =>
            subtle.decrypt({ name: 'AES-GCM', iv, additionalData: ad, tagLength: 128 }, aesKey, ct)]);
    }

    cases.push(['Complete Handshake (classical)', 'crypto core of both sides: 2 keygen, 2 ECDH, sign, verify, 2 hashes, 2 HKDF, 4 HMAC', async () => {
        const c = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
        const s = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
        const zs = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: c.publicKey }, s.privateKey, 256));
        await subtle.digest('SHA-256', transcript);
        await hkdfOp(zs);
        const signature = await subtle.sign({ name: 'Ed25519' }, signer.privateKey, transcript);
        await subtle.sign('HMAC', hmacKey, finishedData);
        if (!await subtle.verify({ name: 'Ed25519' }, signer.publicKey, signature, transcript)) throw new Error('verify');
        const zc = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: s.publicKey }, c.privateKey, 256));
        await subtle.digest('SHA-256', transcript);
        await hkdfOp(zc);
        await subtle.sign('HMAC', hmacKey, finishedData);
        await subtle.sign('HMAC', hmacKey, finishedData);
        await subtle.sign('HMAC', hmacKey, finishedData);
    }]);
    return cases;
}

function nobleCases() {
    const peer = x25519.keygen(), mine = x25519.keygen(), signer = ed25519.keygen();
    const msg = rnd(32), sig = ed25519.sign(msg, signer.secretKey);
    const transcript = rnd(160), ikm = rnd(64), salt = rnd(32), info = rnd(36), finishedData = rnd(117), macKey = rnd(32);
    const aesKey = rnd(32);

    const cases = [
        ['X25519 Key Generation', 'x25519.keygen', () => x25519.keygen()],
        ['X25519 ECDH (Shared Secret)', 'x25519.getSharedSecret', () => x25519.getSharedSecret(mine.secretKey, peer.publicKey)],
        ['Ed25519 Sign', 'ed25519.sign', () => ed25519.sign(msg, signer.secretKey)],
        ['Ed25519 Verify', 'ed25519.verify', () => ed25519.verify(sig, msg, signer.publicKey)],
        ['SHA-256 Transcript Hash', 'sha256 over 160 bytes', () => sha256(transcript)],
        ['HKDF Key Derivation', 'hkdf(sha256), 152 bytes', () => hkdf(sha256, ikm, salt, info, 152)],
        ['Finished MAC', 'hmac(sha256)', () => hmac(sha256, macKey, finishedData)],
    ];

    for (const size of PAYLOAD_SIZES) {
        const data = rnd(size);
        let seq = 0n;
        cases.push([`AES-256-GCM Encrypt (${label(size)})`, 'gcm().encrypt', () => { seq++; return gcm(aesKey, nonce(seq), aad(seq)).encrypt(data); }]);
    }
    for (const size of PAYLOAD_SIZES) {
        const iv = rnd(12), ad = aad(1);
        const ct = gcm(aesKey, iv, ad).encrypt(rnd(size));
        cases.push([`AES-256-GCM Decrypt (${label(size)})`, 'gcm().decrypt including tag check', () => gcm(aesKey, iv, ad).decrypt(ct)]);
    }

    cases.push(['Complete Handshake (classical)', 'crypto core of both sides: 2 keygen, 2 ECDH, sign, verify, 2 hashes, 2 HKDF, 4 HMAC', () => {
        const c = x25519.keygen(), s = x25519.keygen();
        const zs = x25519.getSharedSecret(s.secretKey, c.publicKey);
        sha256(transcript); hkdf(sha256, zs, salt, info, 152);
        const signature = ed25519.sign(transcript, signer.secretKey);
        hmac(sha256, macKey, finishedData);
        if (!ed25519.verify(signature, transcript, signer.publicKey)) throw new Error('verify');
        const zc = x25519.getSharedSecret(c.secretKey, s.publicKey);
        sha256(transcript); hkdf(sha256, zc, salt, info, 152);
        hmac(sha256, macKey, finishedData); hmac(sha256, macKey, finishedData); hmac(sha256, macKey, finishedData);
    }]);
    return cases;
}

async function webCryptoSupport() {
    const result = {};
    for (const name of ['X25519', 'Ed25519']) {
        try {
            await subtle.generateKey({ name }, false, name === 'X25519' ? ['deriveBits'] : ['sign', 'verify']);
            result[name] = true;
        } catch { result[name] = false; }
    }
    return result;
}

// Runs one engine ('webcrypto' or 'noble') and returns a report in the BenchmarkReport format.
export async function run(engine, onProgress) {
    let cases;
    let note = '';
    if (engine === 'webcrypto') {
        const support = await webCryptoSupport();
        if (!support.X25519 || !support.Ed25519)
            throw new Error(`This browser's WebCrypto lacks ${Object.keys(support).filter(k => !support[k]).join(' and ')}.`);
        cases = await webCryptoCases();
        note = 'Every WebCrypto call is awaited, so promise and task-scheduling overhead is included.';
    } else {
        cases = nobleCases();
        note = '@noble/curves, @noble/hashes, @noble/ciphers 2.4.0';
    }

    const results = [];
    for (let i = 0; i < cases.length; i++) {
        const [operation, notes, op] = cases[i];
        onProgress?.(i + 1, cases.length);
        await new Promise(r => setTimeout(r, 30)); // let the page update between cases
        results.push({ Operation: operation, Notes: notes, ...(await measure(op)) });
    }

    return {
        Environment: `JavaScript (${engine === 'webcrypto' ? 'Web Cryptography API' : 'noble, pure JS'}); ${navigator.userAgent}; ` +
            `crossOriginIsolated=${!!globalThis.crossOriginIsolated}; ${note}`,
        Runtime: engine,
        Methodology: 'Batched timing as in KriptoBenchmarks.BenchmarkSuite; statistics over the per-batch values.',
        GeneratedAtUtc: new Date().toISOString(),
        Options: OPTIONS,
        Results: results,
    };
}
