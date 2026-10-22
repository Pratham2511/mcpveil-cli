# Changelog

## 0.3.0

- Bounded recursive argument planning with local references and required constrained siblings; nested SQL/SSRF payload handling corrected.
- Setup diagnostics (`doctor`), measured call latency, readable grouped terminal reports and stable signal fingerprints.
- Ten-case executable accuracy corpus and a real CLI recording replace the simulated demonstration.
- Windows/macOS compatibility CI, and release validation separated from the minimal OIDC publisher job.


## 0.2.0

Compatibility: requires Node >=22.12.0. Report schema 2.0 introduces explicit
assessment status/coverage and nullable scores for incomplete or metadata-only
scans. Stdio credentials now require explicit forwarding.

- Enforce inventory-only mode, tool exclusions, shared call budgets including
  baselines, inventory limits, per-request cancellation and an overall deadline.
- Remove destructive SQL probes; confirm SQL with paired read-only controls and
  command execution with encoded markers resistant to reflected input.
- Sanitize report evidence, target arguments, URLs, supplied credentials and
  buffered target stderr. Isolate the child HOME and restrict inherited env.
- Return execution failure for incomplete assessments and mark SARIF failure
  correctly; report structured-output and metadata coverage honestly.
- Fix CLI validation, config precedence, usage exits, resource/prompt/server
  metadata inspection, API examples and exported report renderers.
- Add independent security regressions and local HTTP/SSE/fallback coverage;
  verify supported runtime installs and clear rejection of Node 18/20.
