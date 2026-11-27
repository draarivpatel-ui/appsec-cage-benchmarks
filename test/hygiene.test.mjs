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

test('public repo contains no local paths, personal mailboxes, co-author trailers or em and en dashes', async () => {
  const emDash = String.fromCodePoint(0x2014);
  const enDash = String.fromCodePoint(0x2013);
  const forbidden = [
    emDash,
    enDash,
    '/' + 'Users' + '/',
    'someone' + '@gmail.com',
    'handle-redacted286' + '@gmail.com',
    '123 Example Street' + ' Manor Drive',
    'Co-Authored' + '-By'
  ];
  const files = await walk(rootDir);
  assert.ok(files.length >= 20, 'hygiene scan must cover the real repository');
  for (const file of files) {
    const text = await readFile(file, 'utf8');
    for (const needle of forbidden) {
      assert.equal(text.includes(needle), false, path.relative(rootDir, file) + ' contains forbidden text ' + JSON.stringify(needle));
    }
  }
});

test('public examples do not use vendor-shaped credential prefixes', async () => {
  const prefixes = [
    'gh' + 'p_',
    'github' + '_pat_',
    'sk' + '-',
    'AK' + 'IA',
    'x' + 'ox',
    'gs' + 'k_',
    'nv' + 'api-',
    'tv' + 'ly-',
    'AI' + 'za',
    'ts' + 'key-'
  ];
  for (const file of await walk(rootDir)) {
    if (path.basename(file) === 'package-lock.json') {
      continue;
    }
    const text = await readFile(file, 'utf8');
    for (const prefix of prefixes) {
      assert.equal(text.includes(prefix), false, path.relative(rootDir, file) + ' contains vendor-shaped prefix');
    }
  }
});

test('dependency manifest pins exactly the ten benchmarked packages', async () => {
  const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  const names = Object.keys(packageJson.dependencies).sort();
  assert.deepEqual(names, [
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
  assert.equal(packageJson.scripts.test, 'node --test test/');
  assert.equal(packageJson.private, true);
});

test('generated report files are ordinary nonempty UTF-8 files', async () => {
  for (const name of ['RESULTS.md', 'results.json', 'README.md']) {
    const info = await stat(new URL('../' + name, import.meta.url));
    assert.equal(info.isFile(), true, name + ' must exist');
    assert.ok(info.size > 500, name + ' must be substantive');
  }
});
