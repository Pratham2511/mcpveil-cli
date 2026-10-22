# Security Policy

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x: — upgrade for safety and reporting repairs |

## Reporting a vulnerability

**Do NOT open a public GitHub issue for security reports.**

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**), or contact the maintainer directly.
Include:

1. The MCPVeil version and the exact command you ran.
2. The target server configuration (command / URL) used to reproduce.
3. The report (`--format json`) or SARIF output demonstrating the issue.
4. Your assessment of impact and suggested fix, if any.

We aim to acknowledge reports within **7 days** and to publish a fix or a
mitigation within **90 days**, with credit to the reporter (unless anonymity
is requested).

## Scope

In scope:

- The `mcpveil` CLI, its transports, checks, and reporters.
- Generated artifacts (JSON / SARIF output) — e.g. injection of attacker-controlled
  strings into reports.
- The GitHub Actions workflows in this repository.

Out of scope:

- The **deliberately vulnerable reference server** under `test/vulnerable-server/`.
  It is a test fixture whose entire purpose is to contain the vulnerabilities
  documented in its source. "Findings" against it are not security issues —
  that is the scanner working as intended. (Its fake credentials are canonical
  documentation examples, not real secrets.)
- Vulnerabilities in the MCP protocol itself (please report those to the
  Model Context Protocol project).
- Social engineering, physical attacks, or denial-of-service volume attacks.

## Repository privacy

Do not commit local account configuration, `.npmrc`, cloud credentials,
private keys, `.env` files, or scan reports containing private data. The
ignore rules protect common local files, and CI scans Git history for
credentials. The npm package includes only its declared distribution files;
`npm run test:package` verifies that private configuration is excluded.

The values in `test/sandbox/seed.ts` and secret-pattern unit tests are
synthetic examples. Test servers create their sandbox under the operating
system's temporary directory; they do not import the maintainer's home files.

Removing personal details from current files does not erase historical Git
author records or previously published npm versions. Report any actual
credential exposure privately and revoke the affected credential.

## Scanner safety model

MCPVeil is an *active* testing tool: it executes the target server and sends
attack payloads through its tools. Our own rules for shipped payloads:

1. **Read-only probe design** — echo-markers instead of destructive
   commands, paired read-only SQL controls; no write statements,
   loopback/metadata markers instead of external exfiltration.
2. **Echo-safe signals** — a success signal must never be satisfiable by a
   server that merely reflects its own input.
3. **Local deterministic detection** — fixture findings are reproducible;
   changing server data or timeouts may change an actual assessment.
4. **Fail honestly** — incomplete coverage and operational errors are ungraded
   and exit nonzero.
5. **Contain target code** — active MCP tools can have side effects regardless
   of probe design. Use disposable data and an external container/VM boundary.

If you are adding a new payload or check, review
[CONTRIBUTING.md](CONTRIBUTING.md)'s destructive-capability checklist first.
