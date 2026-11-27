import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { validateReport } from '../src/benchmark.mjs';

const rootDir = fileURLToPath(new URL('../', import.meta.url));

function percent(rate) {
  return (rate * 100).toFixed(2) + '%';
}

test('committed JSON report has the required schema and perfect correctness summary', async () => {
  const report = JSON.parse(await readFile(new URL('../results.json', import.meta.url), 'utf8'));
  assert.deepEqual(validateReport(report), []);
  assert.equal(report.summary.hostileBlockRate, 1);
  assert.equal(report.summary.benignFalsePositiveRate, 0);
  assert.equal(report.summary.hostileTotal, 80);
  assert.equal(report.summary.benignTotal, 80);
});

test('RESULTS.md and README.md embed numbers from the committed JSON report', async () => {
  const report = JSON.parse(await readFile(new URL('../results.json', import.meta.url), 'utf8'));
  const resultsMarkdown = await readFile(new URL('../RESULTS.md', import.meta.url), 'utf8');
  const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
  for (const suite of report.packages) {
    const row = '| `' + suite.package + '` | ' + suite.version + ' | ' +
      suite.correctness.hostileBlocked + '/' + suite.correctness.hostileTotal + ' (' + percent(suite.correctness.hostileBlockRate) + ') | ' +
      suite.correctness.benignFalsePositives + '/' + suite.correctness.benignTotal + ' (' + percent(suite.correctness.benignFalsePositiveRate) + ') | ' +
      suite.latency.p50Us.toFixed(2) + ' | ' + suite.latency.p95Us.toFixed(2) + ' | ' +
      suite.latency.p99Us.toFixed(2) + ' | ' + suite.latency.opsPerSec.toFixed(2) + ' |';
    assert.ok(resultsMarkdown.includes(row), 'RESULTS.md missing row for ' + suite.package);
    assert.ok(readme.includes(row), 'README.md missing row for ' + suite.package);
  }
});

test('repository root uses the expected public project layout', async () => {
  assert.equal(rootDir.endsWith('appsec-cage-benchmarks' + (process.platform === 'win32' ? '\\' : '/')) || rootDir.endsWith('appsec-cage-benchmarks'), true);
});
