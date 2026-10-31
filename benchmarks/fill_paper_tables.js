// Regenerates the table rows in the paper between "% BEGIN rows:<name>" and "% END rows:<name>".
// Usage: node benchmarks/fill_paper_tables.js <path to main.tex>
const fs = require('fs');
const { execFileSync } = require('child_process');
const path = require('path');

const texPath = process.argv[2];
if (!texPath) throw new Error('usage: node fill_paper_tables.js <main.tex>');

const output = execFileSync('node', [path.join(__dirname, 'make_tables.js')], { encoding: 'utf8' });
const blocks = {};
let current = null;
for (const line of output.split(/\r?\n/)) {
  const header = line.match(/^% ---- tab:(\w+)/);
  if (header) { current = header[1]; blocks[current] = []; continue; }
  if (line.startsWith('% ----') || line.startsWith('% ')) { current = null; continue; }
  if (current && line.trim()) blocks[current].push(line);
}

const names = { primitives: 'native_browser', aes: 'native_browser_aes', js: 'js_baselines', dudect: 'dudect' };
let tex = fs.readFileSync(texPath, 'utf8').replace(/\r\n/g, '\n');
for (const [marker, block] of Object.entries(names)) {
  const re = new RegExp(`(% BEGIN rows:${marker}\\n)[\\s\\S]*?(% END rows:${marker})`);
  if (!re.test(tex)) throw new Error(`markers for ${marker} not found`);
  const rows = (blocks[block] || []).join('\n');
  tex = tex.replace(re, (_, begin, end) => `${begin}${rows}\n${end}`);
}
fs.writeFileSync(texPath, tex);
console.log('table rows written:', Object.fromEntries(Object.entries(names).map(([m, b]) => [m, (blocks[b] || []).length])));
