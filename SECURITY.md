# Security Policy

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

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

## Scanner safety model

MCPVeil is an *active* testing tool: it executes the target server and sends
attack payloads through its tools. Our own rules for shipped payloads:

1. **Non-destructive by construction** — echo-markers instead of destructive
   commands, tautology probes instead of real `DROP TABLE` success paths,
   loopback/metadata markers instead of external exfiltration.
2. **Echo-safe signals** — a success signal must never be satisfiable by a
   server that merely reflects its own input.
3. **No LLM, no randomness** in detection paths — same server + same config =
   same findings.

If you are adding a new payload or check, review
[CONTRIBUTING.md](CONTRIBUTING.md)'s destructive-capability checklist first.
