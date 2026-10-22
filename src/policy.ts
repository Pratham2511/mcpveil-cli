import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { z } from "zod";
import type { Inventory, ScanReport, ScanTarget } from "./types.js";
import { redactValue, redactCommand, redactText } from "./utils/redact.js";
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
  return JSON.stringify(value) ?? "null";
}
export const digest = (value: unknown) => createHash("sha256").update(canonical(value)).digest("hex");
/** Target identity excludes supplied credential values; give each authorization context a distinct logical ID. */
export function targetScope(target: ScanTarget, id: string): string {
  if (!id.trim()) throw new Error("a non-empty --target-id is required for policy artifacts");
  return digest({ id, kind: target.kind, command: target.command ? redactCommand(target.command) : undefined, url: target.url ? redactText(target.url) : undefined });
}
const sha = z.string().regex(/^[a-f0-9]{64}$/);
const BaselineSchema = z.strictObject({
  schemaVersion: z.literal(1), kind: z.literal("mcpveil-baseline"), targetScope: sha,
  createdAt: z.iso.datetime(), expiresAt: z.iso.datetime(), reason: z.string().min(1).max(1000),
  accepted: z.array(z.strictObject({ fingerprint: z.string().regex(/^[a-f0-9]{16,64}$/), severity: z.enum(["critical", "high", "medium", "low", "info"]), confidence: z.enum(["confirmed", "suspicious"]) })).max(10000),
});
export type Baseline = z.infer<typeof BaselineSchema>;
export function readArtifact(path: string): unknown {
  if (statSync(path).size > 1024 * 1024) throw new Error("policy/report input exceeds 1 MiB");
  return JSON.parse(readFileSync(path, "utf8"));
}
export function loadBaseline(path: string): Baseline { return BaselineSchema.parse(readArtifact(path)); }
export function createBaseline(report: ScanReport, id: string, reason: string, expiresAt: string): Baseline {
  if (report.status !== "complete" || report.mode !== "active") throw new Error("baseline creation requires a complete active report");
  if (Date.parse(expiresAt) <= Date.now()) throw new Error("baseline expiry must be in the future");
  return BaselineSchema.parse(redactValue({ schemaVersion: 1, kind: "mcpveil-baseline", targetScope: targetScope(report.target, id),
    createdAt: new Date().toISOString(), expiresAt, reason,
    accepted: report.findings.map(({ fingerprint, severity, confidence }) => ({ fingerprint, severity, confidence })) }));
}
export function validateBaselineTarget(baseline: Baseline, target: ScanTarget, id: string): void {
  BaselineSchema.parse(baseline);
  if (targetScope(target, id) !== baseline.targetScope) throw new Error("baseline target scope mismatch");
  if (Date.parse(baseline.expiresAt) <= Date.now()) throw new Error("baseline expired; review and regenerate it");
}
export function applyBaseline(report: ScanReport, baseline: Baseline, id: string): ScanReport {
  validateBaselineTarget(baseline, report.target, id);
  const keys = new Set(baseline.accepted.map((f) => `${f.fingerprint}:${f.severity}:${f.confidence}`));
  const mark = (f: ScanReport["findings"][number]) => ({ ...f, baselineState: keys.has(`${f.fingerprint}:${f.severity}:${f.confidence}`) ? "accepted" as const : "new" as const });
  return { ...report, findings: report.findings.map(mark), results: report.results.map((result) => ({ ...result, findings: result.findings.map(mark) })),
    policy: { ...report.policy, baseline: { accepted: report.findings.filter((f) => mark(f).baselineState === "accepted").length, total: report.findings.length } } };
}
const SnapshotSchema = z.strictObject({ schemaVersion: z.literal(1), kind: z.literal("mcpveil-tool-snapshot"), targetScope: sha,
  createdAt: z.iso.datetime(), tools: z.record(z.string(), sha) });
export type ToolSnapshot = z.infer<typeof SnapshotSchema>;
export function loadSnapshot(path: string): ToolSnapshot { return SnapshotSchema.parse(readArtifact(path)); }
export function createSnapshot(inv: Inventory, target: ScanTarget, id: string): ToolSnapshot {
  return { schemaVersion: 1, kind: "mcpveil-tool-snapshot", targetScope: targetScope(target, id), createdAt: new Date().toISOString(),
    tools: Object.fromEntries(inv.tools.map((tool) => [digest(tool.name), digest({ name: tool.name, description: tool.description, inputSchema: tool.inputSchema })])) };
}
export function compareSnapshot(snapshot: ToolSnapshot, inv: Inventory, target: ScanTarget, id: string) {
  snapshot = SnapshotSchema.parse(snapshot);
  if (snapshot.targetScope !== targetScope(target, id)) throw new Error("tool snapshot target scope mismatch");
  const current = createSnapshot(inv, target, id).tools;
  return { added: Object.keys(current).filter((key) => !Object.hasOwn(snapshot.tools, key)), removed: Object.keys(snapshot.tools).filter((key) => !Object.hasOwn(current, key)),
    changed: Object.keys(current).filter((key) => Object.hasOwn(snapshot.tools, key) && snapshot.tools[key] !== current[key]) };
}
