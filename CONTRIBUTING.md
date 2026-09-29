# Contributing to MCPVeil

Thanks for helping make MCP server security testing deterministic and boring
(in the way CI gates should be). This document covers how to set up, how we
review, and — most importantly — how to add payloads and checks safely.

## Development setup

```bash
git clone https://github.com/Pratham2511/MCPVeil.git
cd MCPVeil
npm install
npm run build
npm test        # unit + e2e accuracy harness (builds first)
```

Requirements: Node ≥ 18.17 (18/20/22 supported), npm.

Verify your toolchain with the accuracy harness:

```bash
npm run scan:vulnerable   # grade F, exit 1, all six checks fire
npm run scan:safe         # grade A, exit 0, zero findings
```

## Project layout

```
src/
  types.ts            shared contracts — start here
  config/loader.ts    zod-validated config merge
  transports/         stdio | streamable-http | sse (SDK-based)
  engine/             inventory, argPlanner, executor, analyzer, scanner
  checks/             the six registered checks
  payloads/           pure data: payload packs + signal sets
  report/             terminal | json | sarif | score
test/
  sandbox/            deterministic fixture filesystem
  vulnerable-server/  ⚠️ intentionally vulnerable reference server (9 vulns)
  safe-server/        hardened control server (0 findings)
  http-server/        same safe tools over streamable HTTP + SSE
  unit/               engine-level locks
  e2e/                the accuracy harness (CI gate)
```

## The golden rule: the harness is the product

Any change that affects detection (payloads, signals, arg planning, analyzers)
must keep the harness green:

- **100% recall** — every one of the six checks fires against the vulnerable
  server, with confirmed (not merely suspicious) evidence for the headline
  findings.
- **0 false positives** — zero confirmed findings against the hardened control
  server, exit code 0.
- **Determinism** — two consecutive scans produce identical fingerprint sets.

If your PR makes the vulnerable server harder to detect, add a planted
vulnerability fixture that represents the real-world pattern you want caught.

## Adding a payload pack (good first issue)

Most contributions are new entries in `src/payloads/*`. Rules:

1. **Non-destructive.** Payloads must prove *exploitability*, never cause
   damage. Use echo-markers, tautologies, and content canaries — never `rm`,
   real exfil endpoints, or write operations. Run through the checklist below.
2. **Echo-safe.** Your success signal must NOT fire if the server merely
   reflects the payload. Before opening the PR, prove this against the safe
   server: `npm run scan:safe` must exit 0 with zero confirmed findings.
   (Pattern used by the command-injection pack: the raw payload always
   contains `echo <MARKER>`, and the signal uses a lookbehind so reflected
   `echo <MARKER>` text can never match.)
3. **Deterministic.** No timestamps in fingerprints, no network dependencies
   for CI-gating signals.
4. **Documented.** One line per payload: what class of bug it catches.

**Destructive-capability checklist** (confirm every box in the PR description):

- [ ] Payload cannot delete, modify, or exfiltrate data
- [ ] Payload cannot spawn long-running or resource-exhausting processes
- [ ] Payload cannot reach third-party hosts (loopback/canary only)
- [ ] Signal cannot be satisfied by input reflection (echo-safety test)
- [ ] Failure of the payload degrades to "no finding", never to a crash

## Adding a new check

1. Define metadata in `src/checks/registry.ts` and add the id to `CheckId` in
   `src/types.ts`.
2. Implement `run(ctx: ScanContext)` — emit `Finding`s via `ctx.emit`; every
   finding needs a stable fingerprint (`fingerprint([...parts])`).
3. Respect `ctx.active` — static-only checks must not invoke tools.
4. Plant matching vulnerabilities in the vulnerable server and add a
   counterpart defense to the safe server.
5. Update the harness's `REQUIRED_CHECKS` and add unit locks.

## Review process

- CI must be green: lint (strict tsc), unit, e2e harness, on Node 18/20/22.
- One maintainer review for docs/tests; two for new checks or payloads.
- Keep `src/` free of `any` leaks and LLM dependencies (v0.1 contract).

## Code style

- TypeScript strict, ESM (`"type": "module"`), explicit `.js` import
  extensions for relative imports.
- No new runtime dependencies without justification (see
  [SECURITY.md](SECURITY.md) for the payload safety model).

## Reporting bugs

Open a GitHub issue with the exact command, MCPVeil version, target shape,
and the JSON report. **Do not attach real secrets** — reports are masked, but
scrub before pasting. Suspected vulnerabilities in MCPVeil itself go through
[SECURITY.md](SECURITY.md).

## Ethics

MCPVeil is a defensive testing tool. Only scan servers you own or have
written permission to test. PRs that add capability designed to attack
third-party systems will be rejected.
