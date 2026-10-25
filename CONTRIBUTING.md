# Contributing to MCPVeil

Thanks for helping make MCP server security testing deterministic and boring
(in the way CI gates should be). This document covers how to set up, how we
review, and — most importantly — how to add payloads and checks safely.

## Development setup

Clone this repository and open its root directory, then run:

```bash
npm ci
npm run build
npm test        # unit + e2e accuracy harness (builds first)
```

Development requirements: Node 22 (≥22.12.0) and npm for Vitest 5.
The CLI accuracy harness tests supported Node 22/24. Protected legacy job
contexts verify clear rejection of unsupported Node 18/20. To select another installed CLI runtime while keeping Vitest
on Node 22, use an absolute path:

```bash
MCPVEIL_TEST_NODE=/path/to/node24/bin/node npm run test:e2e
```

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
  engine/             inventory, bounded schema/argument planning, executor, analyzer, scanner
  policy.ts           scoped baselines and hashed drift snapshots
  checks/             six content checks plus optional HTTP access policy
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

- **Reference-fixture coverage** — every one of the six checks fires against the vulnerable
  server, with confirmed (not merely suspicious) evidence for the headline
  findings.
- **Safe-fixture control** — zero confirmed findings against the hardened control
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
   The command pack encodes its marker as octal bytes for POSIX printf;
   reflected or whitespace-normalized payloads cannot produce the decoded
   marker on its own output line.
3. **Deterministic.** No timestamps in fingerprints, no network dependencies
   for CI-gating signals.
4. **Documented.** One line per payload: what class of bug it catches.

**Destructive-capability checklist** (confirm every box in the PR description):

- [ ] Payload cannot delete, modify, or exfiltrate data
- [ ] Payload cannot spawn long-running or resource-exhausting processes
- [ ] Payload cannot reach third-party hosts (loopback/canary only)
- [ ] Signal cannot be satisfied by input reflection (echo-safety test)
- [ ] Operational failures produce an incomplete, ungraded scan rather than clean success

## Adding a new check

1. Define metadata in `src/checks/registry.ts` and add the id to `CheckId` in
   `src/types.ts`.
2. Implement `run(ctx: ScanContext)` — emit `Finding`s via `ctx.emit`; every
   finding needs a stable fingerprint (`fingerprint([...parts])`).
3. Respect `ctx.active` — static-only checks must not invoke tools.
4. Plant matching vulnerabilities in the vulnerable server and add a
   counterpart defense to the safe server.
5. Add an independent positive/control fixture and unit locks. Core content
   checks belong in the reference harness; opt-in transport policies use the
   modern HTTP admission fixtures.

## Review process

- CI must be green: lint (strict tsc) and unit tests on Node 22, plus the
  e2e accuracy harness against the CLI and fixture servers on supported Node 22/24.
- One maintainer review for docs/tests; two for new checks or payloads.
- Keep `src/` free of `any` leaks and LLM dependencies.
- Pull requests follow the [PR template](.github/PULL_REQUEST_TEMPLATE.md):
  summary with linked issue, what changed, testing evidence, a compatibility
  note for anything touching a contract (report schema, exit codes, flags,
  budgets), and the checklist.

## AI assistance policy

AI-assisted contributions are welcome — a large share of this project's own
history is AI-assisted and human-reviewed.

- **Disclosure is preferred, not required.** The PR template has an optional
  section: if AI tools helped with code, tests, or docs, a note about which
  parts is appreciated and helps reviewers focus. Choosing not to mention it
  is fine.
- **Ownership always applies.** Whatever tools you used, you review,
  understand, and take responsibility for every line you submit as if you
  wrote it yourself. "The model wrote it" is not a defense for a broken or
  unsafe change.

## Code style

- TypeScript strict, ESM (`"type": "module"`), explicit `.js` import
  extensions for relative imports.
- No new runtime dependencies without justification (see
  [SECURITY.md](SECURITY.md) for the payload safety model).

## Reporting bugs

Open a GitHub issue with the exact command, MCPVeil version, target shape,
and the JSON report. **Do not attach real secrets** — reports are sanitized, but
scrub before pasting. Suspected vulnerabilities in MCPVeil itself go through
[SECURITY.md](SECURITY.md).

## Ethics

MCPVeil is a defensive testing tool. Only scan servers you own or have
written permission to test. PRs that add capability designed to attack
third-party systems will be rejected.

Modern transport tests use the official SDK v2 serving entries. Legacy v1 fixtures
remain process-isolated compatibility controls. `npm run test:package` also runs
the real Action launcher against its exact packed install. Run benchmarks inside
the disposable sandbox; committed timings are measurements of that run, not SLAs.

## Commit identity and completed branches

Before committing, configure this checkout with your own GitHub-linked identity.
For privacy, copy your exact no-reply address from GitHub's email settings;
do not invent or share a generic address. Automated coding tools must use the
identity authorized by the person directing the work.

```bash
git config --local user.name "YOUR_GITHUB_LOGIN"
git config --local user.email "YOUR_GITHUB_NO_REPLY_EMAIL"
git var GIT_AUTHOR_IDENT
git var GIT_COMMITTER_IDENT
```

Review the identity before committing and inspect author/co-author metadata
before publishing. See GitHub's [commit email instructions](https://docs.github.com/en/account-and-profile/how-tos/email-preferences/setting-your-commit-email-address).

After a PR is merged, remove its remote feature branch once its work is
preserved in `main`. Squash merges and history corrections can change commit
IDs; an old branch being reported as ahead does not by itself mean code is
missing. Compare the actual changes with the merged PR before reintegrating it.

If your local checkout predates a history correction, preserve uncommitted work
and local-only commits before resynchronizing from current `main`. Do not merge
or force-push the old history back into the default branch. A fresh checkout
lets you retain the old copy for recovery while starting new work from `main`.

GitHub's contributor sidebar is generated from commit attribution and can lag
behind corrected history. If it remains stale after about 24 hours, the owner
should [contact GitHub Support](https://docs.github.com/en/repositories/viewing-activity-and-data-for-your-repository/viewing-a-projects-contributors#contributor-data-is-stale-after-history-changes).
Deleting and recreating the repository is not a required cleanup step.
