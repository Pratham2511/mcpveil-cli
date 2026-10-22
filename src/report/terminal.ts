import Table from "cli-table3";
import pc from "picocolors";
import type { ScanReport } from "../types.js";
import { redactCommand, redactValue } from "../utils/redact.js";

const SEV_COLOR: Record<string, (s: string) => string> = {
  critical: pc.red, high: pc.red, medium: pc.yellow, low: pc.cyan, info: pc.dim,
};

export function renderTerminal(report: ScanReport): string {
  report = redactValue(report);
  const lines: string[] = [];

  lines.push(pc.bold(`\n◆ MCPVeil v${report.mcpveilVersion} — scan report`));
  lines.push(`status: ${report.status} · mode: ${report.mode}`);
  lines.push(pc.dim(`target: ${describeTarget(report.target)}`));
  lines.push(pc.dim(`server: ${report.serverInfo?.name ?? "unknown"} ${report.serverInfo?.version ?? ""}`));
  lines.push(pc.dim(`inventory: ${report.inventorySizes.tools} tools · ${report.inventorySizes.resources} resources · ${report.inventorySizes.prompts} prompts · ${report.durationMs}ms\n`));

  const table = new Table({
    head: ["Severity", "Check", "Tool/Resource", "Evidence"],
    style: { head: ["bold"], compact: true },
  });
  const groups = new Map<string, { finding: ScanReport["findings"][number]; count: number }>();
  for (const finding of report.findings) {
    const key = `${finding.checkId}:${finding.tool ?? finding.resource ?? "server"}:${finding.severity}:${finding.confidence}`;
    const previous = groups.get(key);
    if (previous) previous.count++; else groups.set(key, { finding, count: 1 });
  }
  for (const { finding: f, count } of groups.values()) {
    const color = SEV_COLOR[f.severity] ?? ((s: string) => s);
    table.push([
      color(f.severity.toUpperCase()),
      f.checkId,
      f.tool ?? f.resource ?? "-",
      `${f.confidence} (${count} signal${count === 1 ? "" : "s"})`,
    ]);
  }
  if (report.findings.length === 0) {
    lines.push(report.status === "complete" ? "No findings within the reported scan scope.\n" : "Assessment incomplete. Absence of findings is not a clean result.\n");
  } else {
    lines.push(table.toString(), "");
    for (const { finding } of [...groups.values()].filter((item, index, all) => all.findIndex((v) => v.finding.checkId === item.finding.checkId) === index)) lines.push(`${finding.checkId}: ${finding.remediation}`);
    lines.push("Full per-probe evidence: use --format json or --format sarif.\n");
  }

  // per-check rollup with invocation counts
  const roll = new Table({ head: ["Check", "Invocations", "Findings", "Errors", "Skipped"], style: { head: ["bold"], compact: true } });
  for (const r of report.results) {
    roll.push([r.meta.id, String(r.invocations), String(r.findings.length), String(r.errors.length), r.skipped ?? "-"]);
  }
  lines.push(roll.toString());

  if (report.score) {
    const gradeColor = report.score.grade === "A" ? pc.green : report.score.grade === "F" ? pc.red : pc.yellow;
    lines.push(`\nPosture score: ${gradeColor(pc.bold(String(report.score.value)))}/100 (grade ${gradeColor(pc.bold(report.score.grade))})`);
  } else lines.push("\nPosture score: ungraded (incomplete or metadata-only assessment)");
  for (const error of report.errors ?? []) lines.push(`Error: ${error}`);
  for (const limitation of report.coverage?.limitations ?? []) lines.push(`Untested: ${limitation}`);
  for (const probe of report.results.flatMap((result) => result.accessProbes ?? [])) lines.push(`Access probe ${probe.name}: ${probe.outcome}`);
  if (report.policy?.baseline) lines.push(`Reviewed baseline: ${report.policy.baseline.accepted}/${report.policy.baseline.total} signals accepted; underlying score retains all risks.`);
  if (report.policy?.drift) lines.push(`Tool drift: ${report.policy.drift.added.length} added, ${report.policy.drift.removed.length} removed, ${report.policy.drift.changed.length} changed (hashes in JSON).`);
  lines.push("");
  return lines.join("\n");
}

function describeTarget(t: ScanReport["target"]): string {
  return t.kind === "stdio" ? `stdio: ${redactCommand(t.command ?? []).join(" ")}` : `${t.kind}: ${t.url}`;
}
