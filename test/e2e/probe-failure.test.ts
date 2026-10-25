/**
 * E2E: per-probe transport failures must be counted, not escalated.
 *
 * The fixture server hangs on payloads containing "etc/passwd" and answers
 * everything else. With a 1s per-request timeout the scan must still finish
 * with status "complete", record the dropped probes in
 * coverage.probeFailures, and exit cleanly — mirroring how a single
 * link-local-blackholed SSRF probe must not fail an otherwise healthy scan.
 */
import { it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { delimiter, dirname, join } from "node:path";
import { tmpdir } from "node:os";
import type { ScanReport } from "../../src/types.js";

const ROOT = process.cwd();
const CLI = join(ROOT, "dist", "cli.js");
const FIXTURE = join(ROOT, "test", "fixtures", "hang-server.mjs");
const TEST_NODE = process.env.MCPVEIL_TEST_NODE || process.execPath;

it("hanging probes are counted in coverage.probeFailures without failing the scan", () => {
  const outDir = mkdtempSync(join(tmpdir(), "mcpveil-hang-"));
  const reportPath = join(outDir, "report.json");
  const res = spawnSync(
    TEST_NODE,
    [
      CLI, "scan",
      "--stdio", `${JSON.stringify(TEST_NODE)} ${JSON.stringify(FIXTURE)}`,
      "--timeout", "1000",
      "--format", "json",
      "-o", reportPath,
      "--yes",
    ],
    { encoding: "utf8", timeout: 120_000, env: { ...process.env, CI: "true", PATH: `${dirname(TEST_NODE)}${delimiter}${process.env.PATH ?? ""}` } },
  );
  expect(existsSync(reportPath), `no report produced (exit=${res.status})\nstderr:\n${res.stderr}\nstdout:\n${res.stdout}`).toBe(true);
  const report = JSON.parse(readFileSync(reportPath, "utf8")) as ScanReport;

  expect(report.status, JSON.stringify({ errors: report.errors, limitations: report.coverage.limitations }, null, 2)).toBe("complete");
  expect(report.errors).toEqual([]);
  expect(report.coverage.toolCalls.echo_text!).toBeGreaterThan(0);
  // Three distinct probes carry "etc/passwd": the absolute traversal value,
  // the SSRF file:// payload, and the credential-leak secret-file probe.
  // Every other probe of the tool is answered.
  expect(report.coverage.probeFailures.echo_text).toBe(3);
  expect(report.coverage.untestedTools).toEqual([]);
  expect(report.findings).toEqual([]);
  expect(res.status).toBe(0);
}, 150_000);
