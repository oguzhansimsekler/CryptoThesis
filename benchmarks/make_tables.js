// Builds the paper's table rows from the benchmark JSON files in this folder.
// Usage: node benchmarks/make_tables.js
// Missing measurements are emitted as \tbd{} so that the gap is visible in the PDF.
// Measurements of the earlier protocol version (no ML-KEM, no Finished) are kept in v2/,
// those of the same protocol on .NET 7 and BouncyCastle 2.6.2 in net7/.
const fs = require('fs');
const path = require('path');

const dir = __dirname;
const files = fs.readdirSync(dir);

// Newest file whose name starts with the given prefix.
function latest(prefix) {
  const match = files.filter(f => f.startsWith(prefix) && f.endsWith('.json')).sort();
  return match.length ? JSON.parse(fs.readFileSync(path.join(dir, match[match.length - 1]), 'utf8')) : null;
}

const sources = {
  native: latest('native-'),
  chromeInterp: latest('wasm-v3-chrome-interpreter-'),
  firefoxInterp: latest('wasm-v3-firefox-interpreter-'),
  chromeAot: latest('wasm-v3-chrome-aot-'),
  firefoxAot: latest('wasm-v3-firefox-aot-'),
  chromeWebCrypto: latest('js-v3-chrome-webcrypto-'),
  firefoxWebCrypto: latest('js-v3-firefox-webcrypto-'),
  chromeNoble: latest('js-v3-chrome-noble-'),
  firefoxNoble: latest('js-v3-firefox-noble-'),
};

const fmt = v => v >= 100 ? v.toFixed(1) : v >= 10 ? v.toFixed(2) : v >= 1 ? v.toFixed(3) : v.toFixed(4);
const fmtSd = v => v < 0.00005 ? '$<$0.0001' : fmt(v);

function cell(report, op, withSd) {
  const r = report?.Results.find(x => x.Operation === op);
  if (!r) return '\\tbd{}';
  return withSd ? `${fmt(r.MeanMs)} (${fmtSd(r.StdDevMs)})` : fmt(r.MeanMs);
}

function table(rows, columns, withSd) {
  return rows.map(row => {
    if (!row) return '\\midrule';
    const [label, op] = row;
    return `${label.padEnd(26)} & ${columns.map(c => cell(sources[c], op, withSd)).join(' & ')} \\\\`;
  }).join('\n');
}

const blazorColumns = ['native', 'chromeInterp', 'firefoxInterp', 'chromeAot', 'firefoxAot'];

const primitiveRows = [
  ['X25519 key generation', 'X25519 Key Generation'],
  ['X25519 shared secret', 'X25519 ECDH (Shared Secret)'],
  ['ML-KEM-768 key generation', 'ML-KEM-768 Key Generation'],
  ['ML-KEM-768 encapsulation', 'ML-KEM-768 Encapsulation'],
  ['ML-KEM-768 decapsulation', 'ML-KEM-768 Decapsulation'],
  ['Ed25519 sign', 'Ed25519 Sign'],
  ['Ed25519 verify', 'Ed25519 Verify'],
  ['SHA-256, 160 bytes', 'SHA-256 Transcript Hash'],
  ['HKDF, 152 bytes', 'HKDF Key Derivation'],
  ['Finished MAC', 'Finished MAC'],
  null,
  ['Handshake, classical', 'Complete Handshake (classical)'],
  ['Handshake, hybrid', 'Complete Handshake (hybrid)'],
];

const aesRows = [];
for (const d of ['Encrypt', 'Decrypt']) {
  for (const kb of [1, 4, 16, 64, 256]) aesRows.push([`${d}, ${kb} KB`, `AES-256-GCM ${d} (${kb} KB)`]);
  if (d === 'Encrypt') aesRows.push(null);
}

const jsRows = [
  ['X25519 key generation', 'X25519 Key Generation'],
  ['X25519 shared secret', 'X25519 ECDH (Shared Secret)'],
  ['Ed25519 sign', 'Ed25519 Sign'],
  ['Ed25519 verify', 'Ed25519 Verify'],
  ['HKDF, 152 bytes', 'HKDF Key Derivation'],
  ['Finished MAC', 'Finished MAC'],
  ['AES-GCM encrypt, 1 KB', 'AES-256-GCM Encrypt (1 KB)'],
  ['AES-GCM encrypt, 64 KB', 'AES-256-GCM Encrypt (64 KB)'],
  ['AES-GCM decrypt, 64 KB', 'AES-256-GCM Decrypt (64 KB)'],
  null,
  ['Handshake, classical', 'Complete Handshake (classical)'],
];
const jsColumns = ['chromeWebCrypto', 'firefoxWebCrypto', 'chromeNoble', 'firefoxNoble', 'chromeAot', 'firefoxAot'];

console.log('% ---- tab:native_browser (primitives and handshakes)');
console.log(table(primitiveRows, blazorColumns, true));
console.log('\n% ---- tab:native_browser_aes');
console.log(table(aesRows, blazorColumns, true));
console.log('\n% ---- tab:js_baselines (means only)');
console.log(table(jsRows, jsColumns, false));

// dudect: |t| range per target. Runs over all targets and the longer runs restricted
// to one target (--only) are reported separately.
const dudectRuns = files.filter(f => f.startsWith('dudect-native-') && f.endsWith('.json')).sort()
  .map(f => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
const tRange = ts => `${Math.min(...ts).toFixed(1)}--${Math.max(...ts).toFixed(1)}`;

const fullRuns = dudectRuns.filter(run => !run.Only);
if (fullRuns.length) {
  console.log(`\n% ---- tab:dudect (${fullRuns.length} runs of ${fullRuns[0].Samples} samples)`);
  for (const r of fullRuns[0].Results) {
    const ts = fullRuns.map(run => run.Results.find(x => x.Operation === r.Operation).MaxAbsT);
    console.log(`${r.Operation} & ${r.Classes} & ${tRange(ts)} \\\\`);
  }
}

const longRuns = dudectRuns.filter(run => run.Only);
if (longRuns.length) {
  console.log('\n% ---- tab:dudect_long (runs restricted to one target)');
  for (const op of [...new Set(longRuns.map(run => run.Results[0].Operation))]) {
    const runs = longRuns.filter(run => run.Results[0].Operation === op);
    const ts = runs.map(run => run.Results[0].MaxAbsT.toFixed(1));
    console.log(`${op} & ${runs.length} $\\times$ $10^{${Math.log10(runs[0].Samples)}}$ & ${ts.join(', ')} \\\\`);
  }
}

console.log('\n% ---- sources');
for (const [k, v] of Object.entries(sources)) console.log(`% ${k}: ${v ? v.Environment.slice(0, 120) : 'missing'}`);
