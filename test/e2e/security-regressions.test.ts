import { it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, existsSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { ScanReport } from "../../src/types.js";

const CLI = join(process.cwd(), "dist/cli.js");
const FIXTURE = join(process.cwd(), "test/fixtures/security-cases.mjs");
const RUNTIME = process.env.MCPVEIL_TEST_NODE || process.execPath;
const FAKE = "ghp_" + "A".repeat(36);
type Event = { event: string; inheritedSyntheticSecret?: boolean; probeTableExists?: boolean };

function scan(mode: string, options: string[] = [], config: Record<string, unknown> = {}, format = "json") {
  const root = mkdtempSync(join(tmpdir(), "mcpveil-regression-"));
  const reportPath = join(root, "report.json");
  const eventsPath = join(root, "events.jsonl");
  const configPath = join(root, "config.json");
  writeFileSync(configPath, JSON.stringify({ timeoutMs: 1000, ...config }));
  try {
    const command = [RUNTIME, FIXTURE, mode, eventsPath].map((value) => JSON.stringify(value)).join(" ");
    const result = spawnSync(RUNTIME, [CLI, "scan", "--stdio", command, "--yes", "--format", format,
      "-o", reportPath, "--config", configPath, ...options], {
      encoding: "utf8", env: { ...process.env, AUDIT_PARENT_SECRET: "synthetic-parent-secret-only" }, timeout: 25000,
    });
    if (result.error) throw result.error;
    const body = existsSync(reportPath) ? readFileSync(reportPath, "utf8") : "";
    const events: Event[] = existsSync(eventsPath) ? readFileSync(eventsPath, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
    return { status: result.status, body, events, stdout: result.stdout, stderr: result.stderr,
      report: body && format === "json" ? JSON.parse(body) as ScanReport : undefined };
  } finally { rmSync(root, { recursive: true, force: true }); }
}

it("inventory-only never invokes tools, resources, or prompt bodies", () => {
  for (const mode of ["echo", "surfaces"]) {
    const result = scan(mode, ["--inventory-only"]);
    expect(result.status).toBe(0);
    expect(result.events.filter((event) => ["call", "read-resource", "get-prompt"].includes(event.event))).toHaveLength(0);
    expect(result.report!.score).toBeNull();
  }
});

it("default SQL probes preserve an existing probe-named table", () => {
  const result = scan("sql-side-effect");
  expect(result.events.some((event) => event.event === "database-state")).toBe(true);
  expect(result.events.some((event) => event.probeTableExists === false)).toBe(false);
});

it("redacts synthetic secrets in every report and strips inherited parent secrets", () => {
  for (const format of ["json", "sarif", "terminal"]) {
    const result = scan("secret", [], {}, format);
    expect(result.status).toBe(1);
    expect(result.body + result.stderr + result.stdout).not.toContain(FAKE);
    expect(result.events[0]!.inheritedSyntheticSecret).toBe(false);
  }
});

it("detects structured-only secrets", () => {
  const result = scan("structured-secret");
  expect(result.status).toBe(1);
  expect(result.report!.findings.some((finding) => finding.checkId === "credential-leak")).toBe(true);
  expect(result.body).not.toContain(FAKE);
});
it("detects and masks opaque credentials identified by structured field names", () => {
  const result = scan("structured-opaque", ["--fail-on", "medium"]);
  expect(result.status).toBe(1);
  expect(result.report!.findings.some((finding) => finding.checkId === "credential-leak")).toBe(true);
  expect(result.body).not.toContain("synthetic-opaque-password-only");
});

it("transport failures and timeouts cannot produce a clean score or successful SARIF", () => {
  for (const mode of ["errors", "hang"]) {
    const result = scan(mode, [], { maxCallsPerTool: 1 });
    expect(result.status).toBe(2);
    expect(result.report!.status).toBe("partial");
    expect(result.report!.score).toBeNull();
    expect(result.report!.errors.length).toBeGreaterThan(0);
  }
  const result = scan("errors", [], { maxCallsPerTool: 1 }, "sarif");
  expect(JSON.parse(result.body).runs[0].invocations[0].executionSuccessful).toBe(false);
});

it("bounds inventory requests with the configured timeout", () => {
  const result = scan("inventory-hang", ["--timeout", "1000"]);
  expect(result.status).toBe(2);
  expect(result.report!.status).toBe("failed");
});

it("enforces one shared call budget and counts baselines", () => {
  const result = scan("echo", [], { maxCallsPerTool: 1 });
  const calls = result.events.filter((event) => event.event === "call");
  expect(calls).toHaveLength(1);
  expect(result.report!.results.reduce((sum, item) => sum + item.invocations, 0)).toBe(1);
  expect(result.report!.coverage.toolCalls.lookup).toBe(1);
  expect(result.status).toBe(2);
});

it("does not confirm injection for literal search or whitespace normalization", () => {
  for (const mode of ["literal-search", "normalize"]) {
    const result = scan(mode);
    expect(result.report!.findings.filter((finding) => finding.confidence === "confirmed" && ["command-injection", "sql-injection"].includes(finding.checkId))).toHaveLength(0);
    expect(result.status).toBe(0);
  }
});

it("active exclusions keep static metadata inspection and true inventory sizes", () => {
  const result = scan("poison", ["--allow-tool", "lookup"]);
  expect(result.events.filter((event) => event.event === "call")).toHaveLength(0);
  expect(result.report!.inventorySizes.tools).toBe(1);
  expect(result.report!.findings.some((finding) => finding.checkId === "prompt-injection")).toBe(true);
});

it("respects explicit CLI > config > default threshold precedence", () => {
  expect(scan("poison", [], { failOn: "low" }).status).toBe(1);
  expect(scan("secret", [], { failOn: "never" }).status).toBe(0);
  expect(scan("poison", ["--fail-on", "never"], { failOn: "low" }).status).toBe(0);
});

it("validates options before starting the target", () => {
  for (const options of [["--fail-on", "invalid"], ["--format", "invalid"], ["--timeout", "1000invalid"],
    ["--skip-check", "invalid"], ["--transport", "sse"], ["--config", "/nonexistent-config.json"]]) {
    const result = scan("echo", options);
    expect(result.status, result.stderr).toBe(3);
    expect(result.events).toHaveLength(0);
  }
});

it("tests deep schemas and finds nested response secrets", () => {
  const result = scan("deep-schema");
  expect(result.status).toBe(1);
  expect(result.report!.coverage.untestedTools).toEqual([]);
  expect(result.report!.findings.some((finding) => finding.checkId === "credential-leak")).toBe(true);
  expect(result.events.some((event: any) => event.args?.request?.options?.query)).toBe(true);
});

it("inspects resources, prompt content, and server instructions", () => {
  const result = scan("surfaces");
  expect(result.report!.findings.some((finding) => finding.checkId === "prompt-injection")).toBe(true);
});
it("does not claim unverified collaborator callbacks or echo-based SSRF", () => {
  const result = scan("echo", [], { ssrfCollaboratorUrl: "https://example.invalid/callback" });
  expect(result.status).toBe(2);
  expect(result.report!.score).toBeNull();
  expect(result.report!.findings.some((finding) => finding.checkId === "ssrf")).toBe(false);
  expect(result.report!.coverage.limitations.join(" ")).toContain("callbacks are not verified");
});

it("rejects hostile inventories, recursive schemas, and oversized or malformed wire data", () => {
  for (const mode of ["duplicate-tools", "many-tools", "cursor-loop", "malformed-inventory", "recursive-schema", "huge-content", "oversized-wire"]) {
    const result = scan(mode, [], { maxCallsPerTool: 1 });
    expect(result.status, `${mode}: ${result.stderr}`).toBe(2);
    expect(result.report!.score).toBeNull();
    expect(result.report!.status).not.toBe("complete");
  }
});
it("forwards synthetic stdio credentials only after explicit selection by name", () => {
  const result = scan("echo", ["--env", "AUDIT_PARENT_SECRET"]);
  expect(result.status).toBe(0);
  expect(result.events[0].inheritedSyntheticSecret).toBe(true);
  expect(result.body).not.toContain("synthetic-parent-secret-only");
});
