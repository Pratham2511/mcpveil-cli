import { it, expect } from "vitest";
import { createBaseline, applyBaseline, createSnapshot, compareSnapshot, targetScope } from "../../src/policy.js";
import { failureReport } from "../../src/engine/scanner.js";
import type { Inventory, ScanReport, Finding } from "../../src/types.js";
const finding: Finding = { checkId: "ssrf", tool: "lookup", severity: "high", confidence: "confirmed", fingerprint: "a".repeat(64), evidence: "marker", title: "test", remediation: "fix" };
function report(): ScanReport {
  return { ...failureReport({ kind: "stdio", command: ["node", "test-server.js"] }, ""), status: "complete", errors: [], mode: "active", findings: [finding], score: { value: 70, grade: "C" } };
}
const future = () => new Date(Date.now() + 86400000).toISOString();
it("accepts only reviewed same-target fingerprints, preserving evidence and the underlying score", () => {
  const original = report();
  const baseline = createBaseline(original, "ci-reader", "Reviewed test exception", future());
  const applied = applyBaseline({ ...original, findings: [...original.findings, { ...finding, fingerprint: "b".repeat(64) }] }, baseline, "ci-reader");
  expect(applied.findings.map((f) => f.baselineState)).toEqual(["accepted", "new"]);
  expect(applied.score).toEqual(original.score);
  expect(original.findings[0].baselineState).toBeUndefined();
  expect(JSON.stringify(baseline)).not.toContain("test-server.js");
  expect(JSON.stringify(baseline)).not.toContain("marker");
});
it("cannot accept escalation, a different authorization context, another target, or an expired exception", () => {
  const r = report(); const baseline = createBaseline(r, "ci-reader", "Review", future());
  expect(applyBaseline({ ...r, findings: [{ ...finding, severity: "critical" }] }, baseline, "ci-reader").findings[0].baselineState).toBe("new");
  expect(() => applyBaseline(r, baseline, "ci-admin")).toThrow(/scope/);
  expect(() => applyBaseline({ ...r, target: { kind: "stdio", command: ["node", "other.js"] } }, baseline, "ci-reader")).toThrow(/scope/);
  expect(() => applyBaseline(r, { ...baseline, expiresAt: "2000-01-01T00:00:00.000Z" }, "ci-reader")).toThrow(/expired/);
});
it("cannot create acceptance from incomplete or inventory reports, or turn partial into success", () => {
  const r = report(); const baseline = createBaseline(r, "ci", "Review", future());
  expect(() => createBaseline({ ...r, status: "partial" }, "ci", "Review", future())).toThrow(/complete active/);
  expect(() => createBaseline({ ...r, mode: "inventory" }, "ci", "Review", future())).toThrow(/complete active/);
  expect(applyBaseline({ ...r, status: "partial", score: null }, baseline, "ci").status).toBe("partial");
});
it("snapshots store only hashes and detect additions, removals, description changes and schema changes", () => {
  const target = { kind: "stdio" as const, command: ["node", "test.js"] };
  const inv: Inventory = { tools: [{ name: "private-tool", description: "private-description", inputSchema: { type: "object", properties: {} }, properties: [], requiredArgNames: [] }], resources: [], prompts: [] };
  const snap = createSnapshot(inv, target, "ci");
  expect(JSON.stringify(snap)).not.toMatch(/private-tool|private-description|test\.js/);
  expect(compareSnapshot(snap, inv, target, "ci")).toEqual({ added: [], removed: [], changed: [] });
  expect(compareSnapshot(snap, { ...inv, tools: [] }, target, "ci").removed).toHaveLength(1);
  for (const changed of [{ ...inv.tools[0], description: "changed" }, { ...inv.tools[0], inputSchema: { type: "object", required: ["new"] } }])
    expect(compareSnapshot(snap, { ...inv, tools: [changed] }, target, "ci").changed).toHaveLength(1);
  expect(compareSnapshot(snap, { ...inv, tools: [...inv.tools, { ...inv.tools[0], name: "new" }] }, target, "ci").added).toHaveLength(1);
  expect(() => compareSnapshot(snap, inv, target, "another-account")).toThrow(/scope/);
});
it("snapshot canonicalization is independent of object key order and scopes by target transport", () => {
  expect(targetScope({ kind: "streamable-http", url: "https://example.invalid/mcp" }, "ci")).not.toBe(targetScope({ kind: "sse", url: "https://example.invalid/mcp" }, "ci"));
});
