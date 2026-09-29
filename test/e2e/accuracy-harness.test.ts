/**
 * ACCURACY HARNESS — the product.
 *
 * Gates CI on scanner accuracy measured against two reference servers:
 *   • vulnerable-server: every one of the six checks must fire (recall = 100%),
 *     with the headline findings CONFIRMED (not merely suspicious).
 *   • safe-server: zero confirmed findings (precision = 100%) and exit code 0.
 *   • determinism: two consecutive scans of the same target produce the exact
 *     same finding fingerprint set.
 *
 * This runs the BUILT CLI (dist/cli.js) — the artifact users actually execute —
 * against the TypeScript fixtures via tsx.
 */
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { existsSync } from "node:fs";
import type { ScanReport, Finding } from "../../src/types.js";

const ROOT = process.cwd();
const CLI = join(ROOT, "dist", "cli.js");
const VULN_SERVER = join(ROOT, "test", "vulnerable-server", "index.ts");
const SAFE_SERVER = join(ROOT, "test", "safe-server", "index.ts");
const TSX = join(ROOT, "node_modules", ".bin", "tsx");

const REQUIRED_CHECKS = [
  "path-traversal",
  "command-injection",
  "sql-injection",
  "ssrf",
  "credential-leak",
  "prompt-injection",
] as const;

function scan(serverPath: string): { status: number | null; report: ScanReport; stderr: string } {
  const outDir = mkdtempSync(join(tmpdir(), "mcpveil-e2e-"));
  const reportPath = join(outDir, "report.json");
  const res = spawnSync(
    process.execPath,
    [
      CLI, "scan",
      "--stdio", `${TSX} ${serverPath}`,
      "--format", "json",
      "-o", reportPath,
      "--yes",
      "--timeout", "6000",
    ],
    { encoding: "utf8", env: { ...process.env, CI: "true" }, timeout: 180_000 }
  );
  if (!existsSync(reportPath)) {
    throw new Error(`no report produced (exit=${res.status})\nstderr:\n${res.stderr}\nstdout:\n${res.stdout}`);
  }
  const report = JSON.parse(readFileSync(reportPath, "utf8")) as ScanReport;
  return { status: res.status, report, stderr: res.stderr ?? "" };
}

function fingerprints(findings: Finding[]): string[] {
  return findings.map((f) => f.fingerprint).sort();
}

describe("accuracy harness (the CI gate)", () => {
  it("vulnerable server: every core check fires with confirmed evidence (recall = 100%)", () => {
    const { status, report, stderr } = scan(VULN_SERVER);

    // exit code contract: findings at/above default --fail-on high → 1
    expect(status, `expected exit 1\n${stderr}`).toBe(1);

    const byCheck = new Set(report.findings.map((f) => f.checkId));
    for (const required of REQUIRED_CHECKS) {
      expect(byCheck.has(required), `missing check: ${required}\nfindings: ${JSON.stringify(report.findings.map(f => ({ checkId: f.checkId, title: f.title, evidence: f.evidence })), null, 2)}`).toBe(true);
    }

    // command injection must be CONFIRMED via executed marker, not echoed payload
    expect(
      report.findings.some((f) => f.checkId === "command-injection" && f.confidence === "confirmed"),
      "no confirmed command-injection"
    ).toBe(true);

    // traversal must be confirmed via canary content or /etc/passwd content
    expect(
      report.findings.some((f) => f.checkId === "path-traversal" && /CANARY|root:/.test(f.evidence)),
      "no confirmed path-traversal evidence"
    ).toBe(true);

    // SQLi must be confirmed via row-blast, not just error text
    expect(
      report.findings.some((f) => f.checkId === "sql-injection" && f.confidence === "confirmed"),
      "no confirmed sql-injection"
    ).toBe(true);

    // SSRF must be confirmed via internal admin marker or file read
    expect(
      report.findings.some((f) => f.checkId === "ssrf" && f.confidence === "confirmed"),
      "no confirmed ssrf"
    ).toBe(true);

    // zero-argument response surfaces (e.g. env-dumpers) must still be actively
    // invoked and response-scanned — regression case for planner v2
    expect(
      report.findings.some((f) => f.checkId === "credential-leak" && f.tool === "dump_env"),
      "zero-argument secret-dumping tool was never actively scanned"
    ).toBe(true);

    expect(report.score.grade).toBe("F");
  }, 200_000);

  it("safe server: zero confirmed findings and clean exit (precision = 100%)", () => {
    const { status, report, stderr } = scan(SAFE_SERVER);

    const confirmed = report.findings.filter((f) => f.confidence === "confirmed");
    expect(
      confirmed,
      `confirmed findings on hardened server:\n${JSON.stringify(confirmed, null, 2)}\nstderr:\n${stderr}`
    ).toHaveLength(0);

    // the control server must also be clean enough to exit 0 under the default policy
    expect(status, `expected exit 0, got ${status}\nfindings:\n${JSON.stringify(report.findings, null, 2)}`).toBe(0);
  }, 200_000);

  it("determinism: two consecutive scans produce identical fingerprint sets", () => {
    const a = scan(VULN_SERVER);
    const b = scan(VULN_SERVER);
    expect(fingerprints(a.report.findings)).toEqual(fingerprints(b.report.findings));
  }, 400_000);
});
