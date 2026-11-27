import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import { runBenchmarks } from '../src/benchmark.mjs';

const rootDir = fileURLToPath(new URL('../', import.meta.url));

test('all hostile corpus cases are blocked with zero benign false positives', { timeout: 120000 }, async () => {
  const report = await runBenchmarks({
    rootDir,
    write: false,
    skipLatency: true,
    iterations: 10,
    warmup: 0
  });

  assert.equal(report.summary.hostileTotal, 144);
  assert.equal(report.summary.benignTotal, 144);
  assert.equal(report.summary.hostileBlocked, 144);
  assert.equal(report.summary.hostileErrors, 0);
  assert.equal(report.summary.benignFalsePositives, 0);
  assert.equal(report.summary.benignErrors, 0);
  assert.equal(report.summary.allHostileBlocked, true);
  assert.equal(report.summary.zeroFalsePositives, true);

  for (const suite of report.packages) {
    assert.equal(suite.correctness.hostileBlockRate, 1, suite.package + ' hostile block rate');
    assert.equal(suite.correctness.benignFalsePositiveRate, 0, suite.package + ' false-positive rate');
    for (const result of suite.cases) {
      assert.equal(result.error, null, suite.package + ' ' + result.id + ' unexpected harness error');
      assert.equal(result.blocked, result.kind === 'hostile', suite.package + ' ' + result.id + ' incorrect disposition');
    }
  }
});
