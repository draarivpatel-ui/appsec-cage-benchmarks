# appsec-cage-benchmarks

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/draarivpatel-ui/appsec-cage-benchmarks/badge)](https://securityscorecards.dev/viewer/?uri=github.com/draarivpatel-ui/appsec-cage-benchmarks)
[![CI](https://github.com/draarivpatel-ui/appsec-cage-benchmarks/actions/workflows/ci.yml/badge.svg)](https://github.com/draarivpatel-ui/appsec-cage-benchmarks/actions/workflows/ci.yml)

An open, reproducible OWASP and CVE security firewall benchmark suite for eighteen published zero-dependency npm packages:

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
- `@aarivbuildz/jwtguard` for explicit-algorithm JWT and JWS verification
- `@aarivbuildz/csrfshield` for signed double-submit CSRF, Origin and Fetch Metadata enforcement
- `@aarivbuildz/hookverify` for webhook signature, timestamp and replay verification
- `@aarivbuildz/urlguard` for SSRF, private-address and redirect-chain validation
- `@aarivbuildz/regex-shield` for ReDoS and catastrophic-backtracking analysis
- `@aarivbuildz/csvshield` for CSV formula-injection detection and neutralization
- `@aarivbuildz/htmlclean` for allowlist HTML sanitization
- `@aarivbuildz/secretsweep` for hard-coded secret and high-entropy credential scanning

Every benchmarked package is installed from the public npm registry at an exact version in `package-lock.json`. None of the eighteen packages has runtime dependencies. The exact installation completed `npm ci` with zero reported vulnerabilities.

## Current measured results

These are real measurements, not estimates. They were produced locally by `npm run bench` on an Apple M5 with 10 CPU cores, darwin arm64, Node.js `v26.8.1`, using 100 warmup calls and 1000 measured calls per package. The benchmark cycled through each suite's complete workload of 8 hostile and 8 benign cases.

| Package | Version | Hostile blocked | Benign false positives | p50 us | p95 us | p99 us | ops/sec |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `sentinel-lint` | 0.2.0 | 8/8 (100.00%) | 0/8 (0.00%) | 400.00 | 887.83 | 1946.88 | 2050.83 |
| `pathcage` | 1.0.1 | 8/8 (100.00%) | 0/8 (0.00%) | 8.50 | 35.54 | 180.96 | 52046.06 |
| `headersafe` | 1.0.1 | 8/8 (100.00%) | 0/8 (0.00%) | 3.79 | 5.54 | 35.13 | 216669.09 |
| `redirectcage` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 5.63 | 27.79 | 115.46 | 68385.81 |
| `envcage` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 19.04 | 57.79 | 104.58 | 41873.56 |
| `cookiecage` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 8.00 | 55.96 | 129.71 | 51652.89 |
| `zipcage` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 50.33 | 287.38 | 640.13 | 10809.72 |
| `logcage` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 5.25 | 15.42 | 50.96 | 102588.22 |
| `corscage` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 14.88 | 43.21 | 112.96 | 47570.44 |
| `jsoncage` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 17.75 | 77.75 | 140.04 | 32300.48 |
| `@aarivbuildz/jwtguard` | 1.0.1 | 8/8 (100.00%) | 0/8 (0.00%) | 50.96 | 147.29 | 336.92 | 14324.64 |
| `@aarivbuildz/csrfshield` | 1.0.1 | 8/8 (100.00%) | 0/8 (0.00%) | 43.04 | 142.58 | 646.17 | 14511.55 |
| `@aarivbuildz/hookverify` | 1.0.1 | 8/8 (100.00%) | 0/8 (0.00%) | 45.46 | 304.29 | 630.83 | 11031.56 |
| `@aarivbuildz/urlguard` | 0.1.0 | 8/8 (100.00%) | 0/8 (0.00%) | 9.50 | 47.58 | 141.38 | 44792.92 |
| `@aarivbuildz/regex-shield` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 16.71 | 107.63 | 437.67 | 25986.77 |
| `@aarivbuildz/csvshield` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 5.29 | 25.92 | 100.21 | 52668.31 |
| `@aarivbuildz/htmlclean` | 0.1.0 | 8/8 (100.00%) | 0/8 (0.00%) | 4.00 | 14.54 | 47.25 | 76687.85 |
| `@aarivbuildz/secretsweep` | 1.0.0 | 8/8 (100.00%) | 0/8 (0.00%) | 33.04 | 292.71 | 2022.75 | 5728.02 |

Aggregate hostile block rate is 100.00% (144/144). Aggregate benign false-positive rate is 0.00% (0/144).

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

Each of the eighteen corpora contains exactly 8 hostile cases and 8 benign controls. Hostile cases are anchored in documented OWASP attack classes, CWE definitions and, where a concrete public vulnerability is directly representative, a specific CVE reference. Benign controls are realistic inputs that should pass the same strict adapter configuration.

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
11. JWT algorithm confusion, dangerous headers, claim omission and parser differentials
12. CSRF token mismatch, expiry, session confusion, Origin bypass and Fetch Metadata rejection
13. webhook signature forgery, malformed encodings, ambiguous headers, stale timestamps and replay
14. SSRF through private IP spellings, metadata endpoints, unsafe schemes, credentials and redirect chains
15. ReDoS nested quantifiers, overlapping alternation, adjacent quantifiers, wildcard chains and nullable loops
16. CSV formula triggers, whitespace and Unicode obfuscation, DDE shapes and CR or LF smuggling
17. HTML script elements, event handlers, dangerous URL schemes, foreign content, srcdoc and inline style risk
18. hard-coded high-entropy assignments, database passwords, JWT-shaped values, private-key blocks and unlabelled tokens

## Enforcement semantics

Security packages use different enforcement styles, so the harness never pretends that every control has the same API shape. Each corpus documents its input and each adapter records the real signal returned by the package.

- `pathcage`, `headersafe`, `envcage` and `cookiecage` count a package error with the documented package error-code namespace as blocked.
- `redirectcage` counts an unsafe parsed redirect location as blocked.
- `zipcage` counts an unsafe inspection report or a package-level ZIP rejection as blocked.
- `logcage` is intentionally neutralization-based. A hostile input is counted as blocked only when the sanitizer observably changes it into safe output. An unchanged input is counted as not blocked.
- `corscage` counts denied cross-origin CORS privileges as blocked. A request with no `Origin` header is treated as non-CORS pass-through, matching the package's documented evaluation semantics.
- `jsoncage` counts an unsafe inspection report as blocked.
- `sentinel-lint` counts one or more scanner findings in the isolated one-file fixture repository as blocked.
- `@aarivbuildz/jwtguard` counts a typed verification rejection as blocked. Hostile tokens are generated before timing so the measured operation is verification, not token construction.
- `@aarivbuildz/csrfshield` counts a structured request-verification rejection as blocked. Tokens and signed cookies are issued before timing.
- `@aarivbuildz/hookverify` counts a typed signature, timestamp, encoding, header or replay rejection as blocked. Provider signatures are generated before timing.
- `@aarivbuildz/urlguard` counts a failed URL or redirect-chain validation as blocked.
- `@aarivbuildz/regex-shield` counts an analysis marked unsafe at medium risk or above as blocked.
- `@aarivbuildz/csvshield` counts one or more formula-injection findings as blocked.
- `@aarivbuildz/htmlclean` is neutralization-based like `logcage`. A hostile input is counted as blocked when sanitization observably changes it or a documented resource limit rejects it.
- `@aarivbuildz/secretsweep` counts one or more scanner findings as blocked. Secret-shaped hostile inputs are deterministic synthetic material generated at runtime, never real credentials.

A benign case is a false positive only when the package blocks or rewrites it under those same semantics. Harness errors are reported separately and fail the correctness gate.

## Latency methodology

Latency uses `process.hrtime.bigint()` directly around every real package call. Corpus fixture creation, ZIP archive specification expansion, sentinel fixture-file creation, JWT construction, CSRF token issuance, webhook signature generation and secretsweep payload materialization happen before timing. The measured work is the package operation itself:

- validation, parsing, evaluation, verification or inspection for library-style APIs
- deterministic hostile ZIP construction plus inspection for `zipcage`
- repository scanning for `sentinel-lint`
- redirect-chain validation for the small number of `urlguard` chain cases
- Ed25519 verification in the one Discord case inside the `hookverify` workload

The percentile implementation is nearest-rank over the measured per-call microsecond samples. Throughput is measured calls divided by measured wall-clock seconds for the timing loop, so it includes real scheduling and harness invocation overhead rather than claiming a theoretical maximum.

## Repository layout

```text
corpora/                  curated hostile and benign inputs for unscoped packages
corpora/@aarivbuildz/     curated hostile and benign inputs for scoped packages
src/run-benchmarks.mjs    command-line benchmark entry point
src/benchmark.mjs         correctness, timing and report generation
src/adapters.mjs          package-specific enforcement adapters
src/corpora.mjs           corpus loading, validation and materialization
test/                     node:test verification suite
results.json              generated machine-readable report
RESULTS.md                generated human-readable report
```

## CI matrix

GitHub Actions runs Ubuntu and Windows on Node.js 18, 20, 22 and 24, for 8 matrix jobs, plus a separate fast-check fuzz job. Every matrix job runs exact dependency installation, the full test suite and the quick benchmark.

## Contributing

Good first contributions include adding well-sourced OWASP or CVE-inspired cases to one corpus, improving documentation of adapter semantics, and adding regression tests for parser differentials. Please keep the 8 hostile plus 8 benign structure intact unless a pull request updates the harness and tests together.

Do not add secret-looking strings with real vendor credential prefixes. Use clearly inert placeholders or deterministic generated material.

## Security

See [`SECURITY.md`](SECURITY.md). The corpus intentionally contains hostile strings as inert test data. They are never executed by the harness.

## License

MIT. See [`LICENSE`](LICENSE).
