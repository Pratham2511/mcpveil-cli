// src/report/sarif.ts
import type { ScanReport, Finding, CheckMeta } from "../types.js";
import { redactValue } from "../utils/redact.js";

const SEV_TO_SARIF: Record<string, "error" | "warning" | "note"> = {
  critical: "error", high: "error", medium: "warning", low: "note", info: "note",
};

/** SARIF 2.1.0 — consumable by GitHub Code Scanning (upload-sarif action). */
export function renderSarif(report: ScanReport): string {
  const metas = new Map<string, CheckMeta>();
  for (const r of report.results) metas.set(r.meta.id, r.meta);

  const rules = [...metas.values()].map((m) => ({
    id: `MCPF/${m.id}`,
    name: m.title,
    shortDescription: { text: m.title },
    fullDescription: { text: m.description },
    help: { text: m.description },
    defaultConfiguration: { level: SEV_TO_SARIF[m.defaultSeverity] ?? "warning" },
    properties: { "security-severity": severityToScore(m.defaultSeverity) },
  }));

  const results = report.findings.map((f) => ({
    ruleId: `MCPF/${f.checkId}`,
    ...(f.baselineState ? { baselineState: f.baselineState === "accepted" ? "unchanged" : "new" } : {}),
    ...(f.baselineState === "accepted" ? { suppressions: [{ kind: "external", status: "accepted", justification: "Reviewed target-scoped MCPVeil baseline" }] } : {}),
    level: SEV_TO_SARIF[f.severity] ?? "note",
    message: {
      text: `${f.title}. Evidence: ${f.evidence}`,
    },
    properties: {
      confidence: f.confidence,
      payload: f.payload ?? "",
      fingerprint: f.fingerprint,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: f.tool ? `mcp://tool/${encodeURIComponent(f.tool)}` : `mcp://resource/${encodeURIComponent(f.resource ?? "server")}`,
          },
        },
        logicalLocations: [{ name: f.tool ?? f.resource ?? "server", kind: "resource" }],
      },
    ],
  }));

  return JSON.stringify(redactValue({
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "MCPVeil",
            version: report.mcpveilVersion,
            informationUri: "https://www.npmjs.com/package/mcpveil-cli",
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: report.status === "complete",
            endTimeUtc: new Date(Date.parse(report.startedAt) + report.durationMs).toISOString(),
            toolExecutionNotifications: (report.errors ?? []).map((error) => ({ level: "error", message: { text: error } })),
          },
        ],
        results,
        properties: { schemaVersion: report.schemaVersion, status: report.status, mode: report.mode, coverage: report.coverage, policy: report.policy, accessProbes: report.results.flatMap((result) => result.accessProbes ?? []) },
      },
    ],
  }), null, 2);
}

function severityToScore(s: string): string {
  // GitHub maps security-severity 0-10 to display priority
  return { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" }[s] ?? "5.0";
}
