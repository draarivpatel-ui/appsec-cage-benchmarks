# Security Policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository instead of filing a public issue for a security problem.

Include the affected package, corpus identifier, reproduction command, Node.js version, operating system, and the smallest input that demonstrates the behavior.

## Scope

This repository is a benchmark harness. Vulnerability reports are in scope for:

- incorrect corpus expectations or source attribution
- benchmark inputs that do not represent the documented attack class
- harness logic that miscounts rejection, neutralization, scanner findings, or false positives
- timing methodology that measures something other than the documented package call
- unsafe handling of temporary benchmark fixtures

The benchmark intentionally contains hostile strings and scanner fixture source in `corpora/`. Those payloads are data, are never executed by the harness, and are not themselves a vulnerability report.
