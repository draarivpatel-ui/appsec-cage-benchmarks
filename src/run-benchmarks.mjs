#!/usr/bin/env node
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { QUICK_ITERATIONS, QUICK_WARMUP, runBenchmarks } from './benchmark.mjs';

function usage() {
  return [
    'Usage: node src/run-benchmarks.mjs [--quick] [--iterations N] [--warmup N]',
    '',
    'Writes RESULTS.md and results.json in the repository root.',
    'Set APPSEC_BENCH_TMP to control where temporary scanner fixtures are created.'
  ].join('\n');
}

function parseArgs(argv) {
  const options = { quick: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--quick') {
      options.quick = true;
    } else if (arg === '--iterations') {
      options.iterations = Number(argv[index + 1]);
      index += 1;
    } else if (arg === '--warmup') {
      options.warmup = Number(argv[index + 1]);
      index += 1;
    } else if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else {
      throw new Error('unknown argument ' + arg + '\n' + usage());
    }
  }
  return options;
}

function percent(rate) {
  return (rate * 100).toFixed(2) + '%';
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log(usage());
    return;
  }
  if (options.quick) {
    options.iterations ??= QUICK_ITERATIONS;
    options.warmup ??= QUICK_WARMUP;
  }
  const report = await runBenchmarks({
    rootDir: fileURLToPath(new URL('../', import.meta.url)),
    quick: options.quick,
    iterations: options.iterations,
    warmup: options.warmup,
    write: true
  });

  console.log('Wrote RESULTS.md and results.json');
  console.log('Hostile block rate: ' + percent(report.summary.hostileBlockRate) + ' (' + report.summary.hostileBlocked + '/' + report.summary.hostileTotal + ')');
  console.log('Benign false-positive rate: ' + percent(report.summary.benignFalsePositiveRate) + ' (' + report.summary.benignFalsePositives + '/' + report.summary.benignTotal + ')');
  for (const suite of report.packages) {
    console.log(suite.package + ': p50 ' + suite.latency.p50Us + ' us, p95 ' + suite.latency.p95Us + ' us, p99 ' + suite.latency.p99Us + ' us, ' + suite.latency.opsPerSec + ' ops/sec');
  }

  if (!report.summary.allHostileBlocked || !report.summary.zeroFalsePositives) {
    process.exitCode = 1;
    console.error('Benchmark correctness gate failed. Inspect results.json for the real failing cases.');
  }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  });
}
