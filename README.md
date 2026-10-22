# MCPVeil

**Local security regression tests for Model Context Protocol servers.**

MCPVeil connects to a real MCP server, inventories its metadata, and runs
bounded security probes. It produces evidence, explicit coverage and completion
status, JSON/SARIF reports, and exit codes for CI. Analysis runs locally without
an LLM or analysis-service API key.

[![npm](https://img.shields.io/npm/v/mcpveil-cli)](https://www.npmjs.com/package/mcpveil-cli)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Node](https://img.shields.io/badge/Node-22.12%2B%20%7C%2024-green)](package.json)

[CI](.github/workflows/ci.yml) · [Security](SECURITY.md) · [Release guide](docs/npm-release.md)

## Install and scan

Use **Node >=22.12.0**; Node 22 and 24 LTS are tested. Node 18/20 are unsupported.

```bash
npm install --global mcpveil-cli
mcpveil --version

# Inventory metadata: no tools/call, resources/read, or prompts/get requests.
mcpveil scan --stdio "node path/to/server.js" --inventory-only --yes

# Active testing of your own disposable test server.
mcpveil scan --stdio "node path/to/server.js" --yes

# Streamable HTTP, with legacy SSE fallback when needed.
mcpveil scan --url http://127.0.0.1:8123/mcp --yes
```

Only contact servers you own or are authorized to test. **Stdio starts server
code even in inventory-only mode.** Active tool calls can have side effects;
use disposable test data and isolate untrusted servers in a container or VM.
An isolated child HOME and filtered environment do not create a filesystem
sandbox. See [safe local testing](docs/sandbox.md).

## What it checks

| Check | Evidence and limits |
|---|---|
| Path traversal | Canary or recognizable file contents returned by crafted paths/resources |
| Command injection | Decoded marker on an output line; marker bytes are encoded in the POSIX probes to resist input reflection |
| SQL injection | Paired read-only true/false conditions compared with a benign baseline; SQL error text is suspicious rather than confirmed |
| SSRF | Response markers from loopback, metadata, or file targets; blind out-of-band callbacks are not verified |
| Credential exposure | Secret-shaped data in metadata, resource/prompt contents, and textual or structured tool responses |
| Prompt injection | Known override phrases and invisible Unicode in tool/schema metadata, resources, prompts, and server instructions |

These are bounded checks, not a proof that a server or an agent is secure.
Prompt-injection heuristics do not establish whether an LLM will follow an
instruction. A credential-shaped match does not validate that a credential is
live. Unsupported schemas, exhausted budgets, truncation, and operational
failures are reported as assessment limitations.

## Reports and CI

```bash
mcpveil scan --stdio "node test-server.js" --yes --format json -o report.json
mcpveil scan --stdio "node test-server.js" --yes --format sarif -o report.sarif
```

| Exit | Meaning |
|---|---|
| 0 | Completed requested assessment; no finding exceeds the configured threshold |
| 1 | Completed assessment with a policy-breaking finding |
| 2 | Failed or partial assessment, including timeout or insufficient coverage |
| 3 | Invalid arguments/configuration, unsupported runtime, or missing consent |

`--fail-on never` disables finding-based failures; it does **not** turn a failed
or incomplete scan into success. Reports include `schemaVersion`, `status`,
`mode`, errors, excluded/untested tools, call counts and limitations. Incomplete
and metadata-only scans have `score: null`; they are not assigned a security
grade. SARIF sets `executionSuccessful: false` for incomplete assessments.

Reports and scanner/target error output are sanitized, including secret-shaped
excerpts, supplied credentials, sensitive command flags, and URL credentials.
Inspect reports before sharing them: arbitrary application data can still be
private without resembling a credential.

## Configuration

Pass `--config mcpveil.config.json` explicitly. Precedence is **explicit CLI
flags > config file > defaults**. Unknown keys and check names are rejected.

```json
{
  "checks": { "ssrf": true, "prompt-injection": true },
  "failOn": "high",
  "timeoutMs": 10000,
  "scanTimeoutMs": 120000,
  "maxCallsPerTool": 128,
  "allowTools": ["create_*", "delete_*"],
  "output": { "format": "json" }
}
```

`maxCallsPerTool` is one shared budget across checks **including benign
baselines**. The allowed range is 1–200. Exhaustion is visible and produces a
partial result. `allowTools` / `--allow-tool` exclude active calls; static
metadata inspection and the true inventory count are retained. A trailing `*`
matches a tool-name prefix.

The default per-request timeout is 10 seconds and the overall deadline is two
minutes. Inventory pagination and content requests are bounded. Timeouts use
SDK cancellation; a target may already have performed work before cancellation.

Stdio targets receive a temporary HOME and a small runtime environment.
Credentials are not inherited implicitly. Forward required variables by name:

```bash
mcpveil scan --stdio "node test-server.js" --env TEST_SERVICE_TOKEN --yes
```

`--env` is repeatable. Use restricted test credentials. `--inventory-only` still
needs `--yes`, and CI does not bypass consent automatically. Run
`mcpveil scan --help` for all supported flags.

## Programmatic API

```js
import { writeFileSync } from "node:fs";
import { connect, runScan, defaultConfig, renderSarif } from "mcpveil-cli";

const target = { kind: "stdio", command: ["node", "path/to/test-server.js"] };
const config = defaultConfig();
const session = await connect(target, { timeoutMs: config.timeoutMs });
try {
  const report = await runScan(session, target, config);
  writeFileSync("report.sarif", renderSarif(report));
  if (report.status !== "complete") throw new Error("Assessment incomplete");
} finally {
  await session.close();
}
```

Pass the **session**, not `session.client`, to `runScan`. The entry point exports
the scanner, connection/inventory/config helpers, and JSON/SARIF/terminal
renderers. API callers authorize their own target connections and should use
the same isolation and credential restrictions as CLI users.

## Test the project

```bash
npm ci
npm run lint
npm test
npm run test:package
```

The suite includes safe and deliberately vulnerable reference servers, real
SQLite side-effect controls, independent reflection/normalization controls,
timeouts and failure status, redaction, budgets, strict CLI policy, and HTTP/SSE
transport tests. Reference-fixture coverage and determinism are CI gates; they
are not general precision/recall percentages. Test servers stay outside the npm
distribution. [Contributing](CONTRIBUTING.md) describes the fixtures and rules.

## Compatibility and migration from 0.1.x

- Node >=22.12.0 is now required, matching runtime dependencies.
- Report schema 2.0 adds completion and coverage fields; `score` may be null.
- The default shared per-tool budget is 128. Existing smaller budgets may
  intentionally produce incomplete coverage.
- Explicit config thresholds are honored, and invalid options are rejected
  before contacting a target.
- Stdio credentials need explicit `--env` forwarding or API `target.env`.
- Keep report consumers aware of assessment status before interpreting a grade.

The bundled SDK currently negotiates legacy MCP revisions through 2025-11-25.
Current-protocol compatibility is tracked separately and is not implied by a
successful connection to a legacy-compatible server.

## Ecosystem and roadmap

[Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner),
[Snyk Agent Scan](https://github.com/snyk/agent-scan), and
[MCP Safety Scanner](https://github.com/leidosinc/McpSafetyScanner) have different
analysis and integration strengths. MCPVeil focuses on local, reproducible
server regression checks. See [ROADMAP.md](ROADMAP.md) for measured accuracy,
onboarding, authenticated transports, baselines and tool-drift work.

## License and security

[MIT](LICENSE). Report vulnerabilities privately through the repository's
Security tab; see [SECURITY.md](SECURITY.md). Do not post reports containing real
credentials or private application data.
