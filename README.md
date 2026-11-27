# appsec-cage-benchmarks

[![CI](https://github.com/draarivpatel-ui/appsec-cage-benchmarks/actions/workflows/ci.yml/badge.svg)](https://github.com/draarivpatel-ui/appsec-cage-benchmarks/actions/workflows/ci.yml)

An open, reproducible OWASP and CVE security firewall benchmark suite for ten published zero-dependency npm packages:

- `sentinel-lint` for dangerous JavaScript and TypeScript security sinks
- `pathcage` for path traversal containment
- `headersafe` for HTTP response-splitting prevention
- `redirectcage` for open redirect validation
- `envcage` for strict environment configuration validation
- `cookiecage` for strict Cookie-header parsing
- `zipcage` for Zip Slip, archive differential and zip-bomb inspection
- `logcage` for CRLF log-injection and terminal-control neutralization
- `corscage` for credentialed CORS origin and preflight enforcement
- `jsoncage` for prototype-pollution, duplicate-key and hostile JSON rejection

Every benchmarked package is installed from the public npm registry at an exact version in `package-lock.json`. None of the ten packages has runtime dependencies. The initial exact installation was audited with `npm audit` and reported zero vulnerabilities.

## Current measured results

These are real measurements, not estimates. They were produced locally by `npm run bench` on an Apple M5 with 10 CPU cores, macOS arm64, Node.js `v26.8.1`, using 100 warmup calls and 1,000 measured calls per package. The benchmark cycled through each suite's complete workload of 8 hostile and 8 benign cases.

| Package | Version | Hostile blocked | Benign false positives | p50 us | p95 us | p99 us | ops/sec |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `sentinel-lint` | 0.2.0 | 8/8 (100.00%) | 0/8 (0.00%) | 453.50 | 1653.63 | 4887.58 | 1425.34 |
| `pathcage` | 1.0.1 | 8/8 (100.00%) | 0/8 (0.00%) | 8.38 | 26.42 | 50.63 | 42907.48 |
| `headersafe` | 1.0.1 | 8/8 (100.00%) | 0/8 (0.00%) | 3.88 | 7.33 | 15.00 | 261805.81 |
| `redirectcage` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 4.00 | 12.46 | 32.92 | 176326.66 |
| `envcage` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 19.21 | 44.58 | 75.50 | 49246.63 |
| `cookiecage` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 5.50 | 22.79 | 75.00 | 116997.84 |
| `zipcage` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 31.08 | 181.83 | 231.71 | 21299.25 |
| `logcage` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 3.83 | 9.50 | 33.88 | 150759.46 |
| `corscage` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 5.54 | 26.58 | 72.50 | 101363.77 |
| `jsoncage` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 7.63 | 36.29 | 77.71 | 74606.68 |

Aggregate hostile block rate is 100.00% (80/80). Aggregate benign false-positive rate is 0.00% (0/80).

Latency varies with CPU, operating system, Node.js version, filesystem speed and machine load. The exact current generated report is in [`RESULTS.md`](RESULTS.md), with machine-readable data in [`results.json`](results.json).

## Reproduce

Requires Node.js 18 or newer.

```sh
npm ci
npm test
npm run bench
```

`npm run bench` rewrites `RESULTS.md` and `results.json` from fresh measurements. CI uses the lower-cost reproduction command:

```sh
npm ci
npm test
npm run bench -- --quick
```

Quick mode still exercises every hostile and benign case. It uses 12 warmup calls and 120 measured calls per package.

## What is measured

Each of the ten corpora contains exactly 8 hostile cases and 8 benign controls. Hostile cases are anchored in documented OWASP attack classes, CWE definitions and, where a concrete public vulnerability is directly representative, a specific CVE reference. Benign controls are realistic inputs that should pass the same strict adapter configuration.

The corpora cover:

1. path traversal and archive-entry containment
2. HTTP response splitting and header-value injection
3. open redirects and return-url confusion
4. environment injection and invalid deployment configuration
5. cookie tossing, cookie smuggling and malformed percent encoding
6. Zip Slip, symlink entries, duplicate entries and compression bombs
7. CRLF log injection, terminal escape sequences and Unicode spoofing
8. credentialed CORS reflection and preflight escalation
9. prototype pollution, duplicate keys, unsafe integers and JSON denial of service
10. eval, raw HTML sinks and shell-command injection in JavaScript and TypeScript

## Enforcement semantics

Security packages use different enforcement styles, so the harness never pretends that every control has the same API shape. Each corpus documents its input and each adapter records the real signal returned by the package.

- `pathcage`, `headersafe`, `envcage` and `cookiecage` count a package error with the documented package error-code namespace as blocked.
- `redirectcage` counts an unsafe parsed redirect location as blocked.
- `zipcage` counts an unsafe inspection report or a package-level ZIP rejection as blocked.
- `logcage` is intentionally neutralization-based. A hostile input is counted as blocked only when the sanitizer observably changes it into safe output. An unchanged input is counted as not blocked.
- `corscage` counts denied cross-origin CORS privileges as blocked. A request with no `Origin` header is treated as non-CORS pass-through, matching the package's documented evaluation semantics.
- `jsoncage` counts an unsafe inspection report as blocked.
- `sentinel-lint` counts one or more scanner findings in the isolated one-file fixture repository as blocked.

A benign case is a false positive only when the package blocks or rewrites it under those same semantics. Harness errors are reported separately and fail the correctness gate.

## Latency methodology

Latency uses `process.hrtime.bigint()` directly around every real package call. Corpus fixture creation, ZIP archive specification expansion and sentinel fixture-file creation happen before timing. The measured work is the package operation itself:

- validation, parsing, evaluation or inspection for library-style APIs
- deterministic hostile ZIP construction plus inspection for `zipcage`
- repository scanning for `sentinel-lint`

The percentile implementation is nearest-rank over the measured per-call microsecond samples. Throughput is measured calls divided by measured wall-clock seconds for the timing loop, so it includes real scheduling and harness invocation overhead rather than claiming a theoretical maximum.

## Repository layout

```text
corpora/                  curated hostile and benign inputs
src/run-benchmarks.mjs    command-line benchmark entry point
src/benchmark.mjs         correctness, timing and report generation
src/adapters.mjs          package-specific enforcement adapters
src/corpora.mjs           corpus loading, validation and materialization
test/                     node:test verification suite
results.json              generated machine-readable report
RESULTS.md                generated human-readable report
```

## CI matrix

GitHub Actions runs Ubuntu and Windows on Node.js 18, 20, 22 and 24, for 8 total jobs. Every job runs exact dependency installation, the full test suite and the quick benchmark.

## Contributing

Good first contributions include adding well-sourced OWASP or CVE-inspired cases to one corpus, improving documentation of adapter semantics, and adding regression tests for parser differentials. Please keep the 8 hostile plus 8 benign structure intact unless a pull request updates the harness and tests together.

Do not add secret-looking strings with real vendor credential prefixes. Use clearly inert placeholders.

## Security

See [`SECURITY.md`](SECURITY.md). The corpus intentionally contains hostile strings as inert test data. They are never executed by the harness.

## License

MIT. See [`LICENSE`](LICENSE).
