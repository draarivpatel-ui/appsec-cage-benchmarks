import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = fileURLToPath(new URL('../', import.meta.url));
const skippedDirectories = new Set(['.git', 'node_modules']);
const textExtensions = new Set(['.json', '.md', '.mjs', '.yml', '.yaml', '.txt', '.gitignore']);

async function walk(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (skippedDirectories.has(entry.name)) {
      continue;
    }
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      output.push(...await walk(fullPath));
    } else if (entry.isFile() && textExtensions.has(path.extname(entry.name))) {
      output.push(fullPath);
    }
  }
  return output;
}

const privacyPatterns = [
  ['email-shaped text', /\b[A-Za-z0-9._%+-]+@(?!(?:[A-Za-z0-9-]+\.)*(?:example\.(?:com|net|org)|example|invalid|test|localhost|internal)\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/],
  ['gaming-handle-shaped text', /\bhandle[-_][A-Za-z0-9_-]*[0-9]{2,}\b/i],
  ['street-address-shaped text', /\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,3}\s(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Court|Ct)\b/],
  ['town-shaped proper name', /\b[A-Z][a-z]+(?:ton|ville|burg|boro|field|wood|ford|shire)\b/],
  ['school-name-shaped text', /\b[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){0,3}\s+(?:High School|Middle School|Elementary School|Academy)\b/]
];

const credentialPatterns = [
  /ghp_[A-Za-z0-9_]+/,
  /github_pat_[A-Za-z0-9_]+/,
  /sk-[A-Za-z0-9_-]{8,}/,
  /AKIA[0-9A-Z]{16}/,
  /xox[baprs]-[A-Za-z0-9-]+/,
  /gsk_[A-Za-z0-9_-]+/,
  /nvapi-[A-Za-z0-9_-]+/,
  /tvly-[A-Za-z0-9_-]+/,
  /AIza[0-9A-Za-z_-]{20,}/,
  /tskey-[A-Za-z0-9_-]+/
];

test('public repo contains no local paths, personal-data-shaped text, co-author trailers or em and en dashes', async () => {
  const emDash = String.fromCodePoint(0x2014);
  const enDash = String.fromCodePoint(0x2013);
  const forbidden = [
    emDash,
    enDash,
    '/' + 'Users' + '/',
    'Co-Authored' + '-By'
  ];
  const files = await walk(rootDir);
  assert.ok(files.length >= 20, 'hygiene scan must cover the real repository');
  for (const file of files) {
    const text = await readFile(file, 'utf8');
    const relative = path.relative(rootDir, file);
    for (const needle of forbidden) {
      assert.equal(text.includes(needle), false, relative + ' contains forbidden text ' + JSON.stringify(needle));
    }
    for (const [label, pattern] of privacyPatterns) {
      assert.equal(pattern.test(text), false, relative + ' contains ' + label);
    }
  }
});

test('public examples do not use vendor-shaped credential material', async () => {
  for (const file of await walk(rootDir)) {
    if (path.basename(file) === 'package-lock.json') {
      continue;
    }
    const text = await readFile(file, 'utf8');
    for (const pattern of credentialPatterns) {
      assert.equal(pattern.test(text), false, path.relative(rootDir, file) + ' contains vendor-shaped credential material');
    }
  }
});

test('dependency manifest pins exactly the eighteen benchmarked packages', async () => {
  const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  const names = Object.keys(packageJson.dependencies).sort();
  assert.deepEqual(names, [
    '@aarivbuildz/csrfshield',
    '@aarivbuildz/csvshield',
    '@aarivbuildz/hookverify',
    '@aarivbuildz/htmlclean',
    '@aarivbuildz/jwtguard',
    '@aarivbuildz/regex-shield',
    '@aarivbuildz/secretsweep',
    '@aarivbuildz/urlguard',
    'cookiecage',
    'corscage',
    'envcage',
    'headersafe',
    'jsoncage',
    'logcage',
    'pathcage',
    'redirectcage',
    'sentinel-lint',
    'zipcage'
  ]);
  for (const [name, version] of Object.entries(packageJson.dependencies)) {
    assert.match(version, /^\d+\.\d+\.\d+$/, name + ' must be exactly pinned');
  }
  assert.equal(packageJson.scripts.bench, 'node src/run-benchmarks.mjs');
  assert.equal(packageJson.scripts.test, 'node --test test/corpora.test.mjs test/detection.test.mjs test/hygiene.test.mjs test/report.test.mjs');
  assert.equal(packageJson.private, true);
});

test('generated report files are ordinary nonempty UTF-8 files', async () => {
  for (const name of ['RESULTS.md', 'results.json', 'README.md']) {
    const info = await stat(new URL('../' + name, import.meta.url));
    assert.equal(info.isFile(), true, name + ' must exist');
    assert.ok(info.size > 500, name + ' must be substantive');
  }
});
