# Roadmap

v0.1.0 ships the deterministic active-scanning core plus the accuracy harness.
Everything below is ordered by demand signal, not by difficulty.

## v0.2 — CI ergonomics

1. **Baseline suppression** (`--baseline mcpveil-baseline.json`): commit the
   fingerprint set of known-accepted findings; new findings still fail the
   gate. Fingerprints are already in v0.1 reports — baselines are
   forward-compatible today.
2. **First-party GitHub Action** (`mcpveil/action@v1`) wrapping the
   build → scan → upload-sarif loop, plus GitLab CI template and a pre-commit
   hook.
3. **`--min-severity` reporting filter** distinct from `--fail-on` gating.

## v0.3 — detection surface

4. **More payload packs** (community-driven, see CONTRIBUTING "add a payload
   pack"): YAML deserialization gadget probes, zip-slip archive paths, path
   traversal via resource templates, prototype pollution in object args.
5. **Tool-drift / rug-pull detection**: hash `tools/list` across scans; diff
   descriptions and schemas; fail on silent edits (the "invisible unicode"
   class is already detected statically — drift detection closes the
   runtime-edit gap).
6. **Authentication & transport checks**: missing/weak auth on HTTP
   transports, plaintext HTTP targets, session-token reuse — extends the
   published 38–41% unauthenticated-server finding.
7. **Confused-deputy checks** (per the ACM 2026 paper): cross-server
   attribution probing when a session exposes multiple servers.

## v0.4 — performance benchmarking (the unique wedge)

8. **`mcpveil bench`**: p50/p95/p99 tool-call latency, concurrency
   throughput, memory pegging over long sessions; regression gates for
   server authors. No verified competitor ships this.

## v0.5 — optional semantics

9. **`--semantic` LLM triage hook** for `suspicious` findings only — the
   deterministic core stays LLM-free; the hook never gates CI by default.

## Research track

10. **Registry crawler + leaderboard**: scan public MCP server registries
    with consented targets and publish aggregate posture statistics (the
    next "82% of servers…" headline, generated reproducibly).
11. **Accuracy harness as a public benchmark**: publish the vulnerable/safe
    server pair as a standard accuracy target so any MCP security tool —
    including competitors — can publish recall/precision numbers we can
    compare.
