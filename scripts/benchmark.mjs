import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import assert from "node:assert/strict";
// Synthetic targets only. Run this command inside the documented disposable sandbox.
const cases = [
  ["echo", []], ["normalize", []], ["literal-search", []],
  ["secret", ["credential-leak"]], ["structured-secret", ["credential-leak"]],
  ["structured-opaque", ["credential-leak"]], ["deep-schema", ["credential-leak"]],
  ["poison", ["prompt-injection"]], ["surfaces", ["prompt-injection"]],
  ["sql-side-effect", ["sql-injection"]],
];
const results = cases.map(([name, expected]) => {
  const result = spawnSync(process.execPath, ["dist/cli.js", "scan", "--stdio", `${JSON.stringify(process.execPath)} test/fixtures/security-cases.mjs ${name}`,
    "--yes", "--format", "json", "--fail-on", "medium"], { encoding: "utf8", timeout: 30000 });
  assert(!result.error, result.error?.message);
  const report = JSON.parse(result.stdout);
  const actual = [...new Set(report.findings.map((finding) => finding.checkId))].sort();
  assert.equal(report.status, "complete", `${name}: incomplete`);
  assert.deepEqual(actual, [...expected].sort(), `${name}: unexpected detection`);
  assert.equal(result.status, expected.length ? 1 : 0, `${name}: incorrect exit`);
  return { case: name, expected, detected: actual, passed: true, durationMs: report.durationMs,
    calls: Object.values(report.coverage.toolCalls).reduce((a, b) => a + b, 0), latencyMs: report.coverage.latencyMs };
});
const output = { schemaVersion: 1, packageVersion: JSON.parse(readFileSync("package.json")).version, node: process.version,
  scope: "Ten labeled synthetic local cases. This is fixture coverage, not population precision/recall or proof of security.", results };
const destination = process.argv[2];
if (destination) writeFileSync(destination, JSON.stringify(output, null, 2) + "\n");
console.log(JSON.stringify(output, null, 2));
