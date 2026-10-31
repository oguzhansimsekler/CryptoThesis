// Builds the paper's table rows and browser/native ratios from the benchmark JSON files.
// Usage: node benchmarks/make_tables.js
const fs = require('fs');
const path = require('path');

const dir = __dirname;
const load = f => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
const columns = [
  ['Native .NET', load('native-20261030-125228.json')],
  ['Chrome, interp.', load('wasm-chrome156-interpreter-20261030-132824.json')],
  ['Firefox, interp.', load('wasm-firefox159-interpreter-20261030-132935.json')],
  ['Chrome, AOT', load('wasm-chrome156-aot-20261030-133056.json')],
  ['Firefox, AOT', load('wasm-firefox159-aot-20261030-133130.json')],
];

const rows = [
  ['X25519 key generation', 'X25519 Key Generation'],
  ['X25519 shared secret', 'X25519 ECDH (Shared Secret)'],
  ['Ed25519 sign', 'Ed25519 Sign'],
  ['Ed25519 verify', 'Ed25519 Verify'],
  ['SHA-256, 160 bytes', 'SHA-256 Transcript Hash'],
  ['HKDF, 88 bytes', 'HKDF Key Derivation'],
  null,
  ['Complete handshake', 'Complete Secure Handshake'],
];
const aesRows = [];
for (const dirn of ['Encrypt', 'Decrypt']) {
  for (const kb of [1, 4, 16, 64, 256]) aesRows.push([`${dirn}, ${kb} KB`, `AES-256-GCM ${dirn} (${kb} KB)`]);
  if (dirn === 'Encrypt') aesRows.push(null);
}

const get = (report, op) => {
  const r = report.Results.find(x => x.Operation === op);
  if (!r) throw new Error(`missing ${op}`);
  return r;
};
// Four decimals below 1 ms, three significant digits above.
const fmt = v => v >= 100 ? v.toFixed(1) : v >= 10 ? v.toFixed(2) : v >= 1 ? v.toFixed(3) : v.toFixed(4);
const fmtSd = v => v < 0.00005 ? '$<$0.0001' : fmt(v);

const table = list => list.map(row => {
  if (!row) return '\\midrule';
  const [label, op] = row;
  const cells = columns.map(([, rep]) => { const r = get(rep, op); return `${fmt(r.MeanMs)} (${fmtSd(r.StdDevMs)})`; });
  return `${label.padEnd(22)} & ${cells.join(' & ')} \\\\`;
}).join('\n');

console.log('% ---- tab:native_browser\n' + table(rows));
console.log('\n% ---- tab:native_browser_aes\n' + table(aesRows));

console.log('\n% ---- slowdown relative to native (mean / native mean)');
const native = columns[0][1];
for (const row of [...rows, ...aesRows].filter(Boolean)) {
  const n = get(native, row[1]).MeanMs;
  const ratios = columns.slice(1).map(([name, rep]) => `${name}: ${(get(rep, row[1]).MeanMs / n).toFixed(2)}x`);
  console.log(`${row[0].padEnd(22)} ${ratios.join('  ')}`);
}
for (const [name, rep] of columns) console.log(`${name}: ${rep.Environment}`);
