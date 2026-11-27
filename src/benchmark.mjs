import { mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { createAdapters } from './adapters.mjs';
import { corpusCases, loadCorpora, materializeInput, readPackageVersions } from './corpora.mjs';

export const DEFAULT_ITERATIONS = 1000;
export const DEFAULT_WARMUP = 100;
export const QUICK_ITERATIONS = 120;
export const QUICK_WARMUP = 12;

function round(value, places = 3) {
  const factor = 10 ** places;
  return Math.round(value * factor) / factor;
}

function percentile(sorted, percentileValue) {
  if (sorted.length === 0) {
    return 0;
  }
  const rank = Math.ceil((percentileValue / 100) * sorted.length);
  const index = Math.max(0, Math.min(sorted.length - 1, rank - 1));
  return sorted[index];
}

function consumeResult(state, result) {
  const text = String(result && result.blocked) + '|' + String(result && result.signal) + '|' + String(result && result.outputLength);
  let hash = state >>> 0;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return hash >>> 0;
}

async function invokeAdapter(adapter, benchCase) {
  if (adapter.async) {
    return adapter.invoke(benchCase);
  }
  return adapter.invoke(benchCase);
}

async function prepareCases(corpus, adapter, context) {
  const preparedCases = [];
  for (const entry of corpusCases(corpus)) {
    const input = materializeInput(entry.input);
    const prepared = adapter.prepare
      ? await adapter.prepare(input, entry, context)
      : input;
    preparedCases.push({
      id: entry.id,
      title: entry.title,
      kind: entry.kind,
      cwe: entry.cwe || null,
      input,
      prepared
    });
  }
  return preparedCases;
}

export async function evaluateCorrectness(adapter, cases) {
  const results = [];
  for (const benchCase of cases) {
    try {
      const outcome = await invokeAdapter(adapter, benchCase);
      results.push({
        id: benchCase.id,
        kind: benchCase.kind,
        blocked: outcome.blocked === true,
        signal: String(outcome.signal || 'unspecified'),
        error: null
      });
    } catch (error) {
      results.push({
        id: benchCase.id,
        kind: benchCase.kind,
        blocked: false,
        signal: 'harness-error',
        error: {
          name: error && error.name ? error.name : 'Error',
          code: error && typeof error.code === 'string' ? error.code : null
        }
      });
    }
  }
  return results;
}

export function summarizeCorrectness(caseResults) {
  const hostile = caseResults.filter((result) => result.kind === 'hostile');
  const benign = caseResults.filter((result) => result.kind === 'benign');
  const hostileBlocked = hostile.filter((result) => result.blocked && !result.error).length;
  const hostileErrors = hostile.filter((result) => result.error).length;
  const benignFalsePositives = benign.filter((result) => result.blocked && !result.error).length;
  const benignErrors = benign.filter((result) => result.error).length;
  return {
    hostileTotal: hostile.length,
    hostileBlocked,
    hostileErrors,
    hostileBlockRate: hostile.length === 0 ? 0 : hostileBlocked / hostile.length,
    benignTotal: benign.length,
    benignFalsePositives,
    benignErrors,
    benignFalsePositiveRate: benign.length === 0 ? 0 : benignFalsePositives / benign.length,
    caseCount: caseResults.length
  };
}

export async function measureLatency(adapter, cases, options = {}) {
  const iterations = options.iterations ?? DEFAULT_ITERATIONS;
  const warmup = options.warmup ?? DEFAULT_WARMUP;
  if (!Number.isSafeInteger(iterations) || iterations < 10) {
    throw new Error('iterations must be a safe integer of at least 10');
  }
  if (!Number.isSafeInteger(warmup) || warmup < 0) {
    throw new Error('warmup must be a nonnegative safe integer');
  }
  if (cases.length === 0) {
    throw new Error('latency measurement requires at least one case');
  }

  let checksum = 0;
  for (let index = 0; index < warmup; index += 1) {
    const benchCase = cases[index % cases.length];
    const outcome = adapter.async ? await adapter.invoke(benchCase) : adapter.invoke(benchCase);
    checksum = consumeResult(checksum, outcome);
  }

  const samples = [];
  const wallStart = process.hrtime.bigint();
  if (adapter.async) {
    for (let index = 0; index < iterations; index += 1) {
      const benchCase = cases[index % cases.length];
      const start = process.hrtime.bigint();
      const outcome = await adapter.invoke(benchCase);
      const end = process.hrtime.bigint();
      checksum = consumeResult(checksum, outcome);
      samples.push(Number(end - start) / 1000);
    }
  } else {
    for (let index = 0; index < iterations; index += 1) {
      const benchCase = cases[index % cases.length];
      const start = process.hrtime.bigint();
      const outcome = adapter.invoke(benchCase);
      const end = process.hrtime.bigint();
      checksum = consumeResult(checksum, outcome);
      samples.push(Number(end - start) / 1000);
    }
  }
  const wallSeconds = Number(process.hrtime.bigint() - wallStart) / 1e9;
  const sorted = [...samples].sort((left, right) => left - right);
  const total = samples.reduce((sum, sample) => sum + sample, 0);
  return {
    iterations,
    warmup,
    workloadCases: cases.length,
    minUs: round(sorted[0]),
    p50Us: round(percentile(sorted, 50)),
    p95Us: round(percentile(sorted, 95)),
    p99Us: round(percentile(sorted, 99)),
    maxUs: round(sorted[sorted.length - 1]),
    meanUs: round(total / samples.length),
    opsPerSec: round(samples.length / wallSeconds, 2),
    checksum
  };
}

function environmentInfo() {
  const cpus = os.cpus();
  return {
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    cpuModel: cpus.length > 0 ? cpus[0].model : 'unknown',
    cpuCount: cpus.length,
    nodeVersion: process.version
  };
}

function aggregateSuites(suites) {
  const hostileTotal = suites.reduce((sum, suite) => sum + suite.correctness.hostileTotal, 0);
  const hostileBlocked = suites.reduce((sum, suite) => sum + suite.correctness.hostileBlocked, 0);
  const hostileErrors = suites.reduce((sum, suite) => sum + suite.correctness.hostileErrors, 0);
  const benignTotal = suites.reduce((sum, suite) => sum + suite.correctness.benignTotal, 0);
  const benignFalsePositives = suites.reduce((sum, suite) => sum + suite.correctness.benignFalsePositives, 0);
  const benignErrors = suites.reduce((sum, suite) => sum + suite.correctness.benignErrors, 0);
  return {
    packageCount: suites.length,
    hostileTotal,
    hostileBlocked,
    hostileErrors,
    hostileBlockRate: hostileTotal === 0 ? 0 : hostileBlocked / hostileTotal,
    benignTotal,
    benignFalsePositives,
    benignErrors,
    benignFalsePositiveRate: benignTotal === 0 ? 0 : benignFalsePositives / benignTotal,
    allHostileBlocked: hostileBlocked === hostileTotal && hostileErrors === 0,
    zeroFalsePositives: benignFalsePositives === 0 && benignErrors === 0
  };
}

export function buildReport(suites, options) {
  const report = {
    schemaVersion: 1,
    benchmark: {
      name: 'appsec-cage-benchmarks',
      command: 'npm run bench',
      quickCommand: 'npm run bench -- --quick',
      iterations: options.iterations,
      warmup: options.warmup,
      quick: options.quick === true
    },
    environment: environmentInfo(),
    packages: suites,
    summary: aggregateSuites(suites)
  };
  return report;
}

function percent(rate) {
  return (rate * 100).toFixed(2) + '%';
}

function numberCell(value) {
  return Number(value).toFixed(2);
}

export function renderResultsMarkdown(report) {
  const lines = [];
  lines.push('# Benchmark Results');
  lines.push('');
  lines.push('Generated by `npm run bench`. Do not edit this file by hand.');
  lines.push('');
  lines.push('## Environment');
  lines.push('');
  lines.push('| CPU | Cores | Platform | Arch | Node | Measured calls | Warmup calls |');
  lines.push('| --- | ---: | --- | --- | --- | ---: | ---: |');
  lines.push('| ' + report.environment.cpuModel + ' | ' + report.environment.cpuCount + ' | ' + report.environment.platform + ' ' + report.environment.release + ' | ' + report.environment.arch + ' | ' + report.environment.nodeVersion + ' | ' + report.benchmark.iterations + ' per package | ' + report.benchmark.warmup + ' per package |');
  lines.push('');
  lines.push('Reproduce with `npm ci && npm run bench`. CI uses `npm ci && npm test && npm run bench -- --quick`. Latency uses `process.hrtime.bigint()` around each real package call and cycles through the complete hostile plus benign workload.');
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push('| Package | Version | Hostile blocked | Benign false positives | p50 us | p95 us | p99 us | ops/sec |');
  lines.push('| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |');
  for (const suite of report.packages) {
    lines.push('| `' + suite.package + '` | ' + suite.version + ' | ' + suite.correctness.hostileBlocked + '/' + suite.correctness.hostileTotal + ' (' + percent(suite.correctness.hostileBlockRate) + ') | ' + suite.correctness.benignFalsePositives + '/' + suite.correctness.benignTotal + ' (' + percent(suite.correctness.benignFalsePositiveRate) + ') | ' + numberCell(suite.latency.p50Us) + ' | ' + numberCell(suite.latency.p95Us) + ' | ' + numberCell(suite.latency.p99Us) + ' | ' + numberCell(suite.latency.opsPerSec) + ' |');
  }
  lines.push('');
  lines.push('Aggregate hostile block rate: ' + percent(report.summary.hostileBlockRate) + ' (' + report.summary.hostileBlocked + '/' + report.summary.hostileTotal + '). Aggregate benign false-positive rate: ' + percent(report.summary.benignFalsePositiveRate) + ' (' + report.summary.benignFalsePositives + '/' + report.summary.benignTotal + ').');
  lines.push('');
  lines.push('## Per-suite case results');
  for (const suite of report.packages) {
    lines.push('');
    lines.push('### ' + suite.package);
    lines.push('');
    lines.push(suite.title + '. Primary weakness: ' + suite.primaryCwe + '.');
    lines.push('');
    lines.push('| Case | Kind | Blocked | Signal |');
    lines.push('| --- | --- | --- | --- |');
    for (const result of suite.cases) {
      lines.push('| `' + result.id + '` | ' + result.kind + ' | ' + String(result.blocked) + ' | `' + result.signal + '` |');
    }
  }
  lines.push('');
  return lines.join('\n');
}

export function validateReport(report) {
  const errors = [];
  if (!report || typeof report !== 'object') {
    return ['report must be an object'];
  }
  if (report.schemaVersion !== 1) {
    errors.push('schemaVersion must be 1');
  }
  if (!report.benchmark || !Number.isSafeInteger(report.benchmark.iterations) || !Number.isSafeInteger(report.benchmark.warmup)) {
    errors.push('benchmark iteration metadata is missing');
  }
  if (!report.environment || typeof report.environment.nodeVersion !== 'string' || typeof report.environment.cpuModel !== 'string') {
    errors.push('environment metadata is missing');
  }
  if (!Array.isArray(report.packages) || report.packages.length !== 10) {
    errors.push('report must contain exactly ten package suites');
  } else {
    for (const suite of report.packages) {
      if (typeof suite.package !== 'string' || typeof suite.version !== 'string') {
        errors.push('suite is missing package or version');
      }
      for (const key of ['hostileBlockRate', 'benignFalsePositiveRate']) {
        if (!suite.correctness || typeof suite.correctness[key] !== 'number' || suite.correctness[key] < 0 || suite.correctness[key] > 1) {
          errors.push(suite.package + ' has invalid ' + key);
        }
      }
      for (const key of ['p50Us', 'p95Us', 'p99Us', 'opsPerSec']) {
        if (!suite.latency || !Number.isFinite(suite.latency[key]) || suite.latency[key] <= 0) {
          errors.push(suite.package + ' has invalid latency field ' + key);
        }
      }
      if (!Array.isArray(suite.cases) || suite.cases.length !== suite.correctness.caseCount) {
        errors.push(suite.package + ' case results do not match correctness count');
      }
    }
  }
  if (!report.summary || typeof report.summary.hostileBlockRate !== 'number' || typeof report.summary.benignFalsePositiveRate !== 'number') {
    errors.push('aggregate summary is missing');
  }
  return errors;
}

export async function runBenchmarks(options = {}) {
  const rootDir = options.rootDir || fileURLToPath(new URL('../', import.meta.url));
  const quick = options.quick === true;
  const iterations = options.iterations ?? (quick ? QUICK_ITERATIONS : DEFAULT_ITERATIONS);
  const warmup = options.warmup ?? (quick ? QUICK_WARMUP : DEFAULT_WARMUP);
  const tmpRoot = options.tmpRoot || process.env.APPSEC_BENCH_TMP || os.tmpdir();
  await mkdir(tmpRoot, { recursive: true });
  const workDir = path.join(tmpRoot, 'appsec-cage-' + process.pid + '-' + Date.now());
  await mkdir(workDir, { recursive: true });

  try {
    const corpora = await loadCorpora(rootDir);
    const versions = await readPackageVersions(rootDir);
    const adapters = createAdapters({ workDir, rootDir });
    const suites = [];
    for (const corpus of corpora) {
      const adapter = adapters[corpus.package];
      if (!adapter) {
        throw new Error('no adapter registered for ' + corpus.package);
      }
      const cases = await prepareCases(corpus, adapter, { workDir, rootDir });
      const caseResults = await evaluateCorrectness(adapter, cases);
      const correctness = summarizeCorrectness(caseResults);
      const latency = options.skipLatency
        ? {
            iterations: 0,
            warmup: 0,
            workloadCases: cases.length,
            minUs: 1,
            p50Us: 1,
            p95Us: 1,
            p99Us: 1,
            maxUs: 1,
            meanUs: 1,
            opsPerSec: 1,
            checksum: 0
          }
        : await measureLatency(adapter, cases, { iterations, warmup });
      suites.push({
        package: corpus.package,
        version: versions[corpus.package],
        title: corpus.title,
        attackSurface: corpus.attackSurface,
        primaryCwe: corpus.primaryCwe,
        references: corpus.references,
        correctness,
        latency,
        cases: caseResults
      });
    }
    const report = buildReport(suites, { iterations, warmup, quick });
    const schemaErrors = validateReport(report);
    if (schemaErrors.length > 0) {
      throw new Error('generated report failed schema validation:\n' + schemaErrors.join('\n'));
    }
    if (options.write !== false) {
      await writeFile(path.join(rootDir, 'results.json'), JSON.stringify(report, null, 2) + '\n', 'utf8');
      await writeFile(path.join(rootDir, 'RESULTS.md'), renderResultsMarkdown(report), 'utf8');
    }
    return report;
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
}
