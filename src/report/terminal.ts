import Table from "cli-table3";
import pc from "picocolors";
import type { ScanReport } from "../types.js";

const SEV_COLOR: Record<string, (s: string) => string> = {
  critical: pc.red, high: pc.red, medium: pc.yellow, low: pc.cyan, info: pc.dim,
};

export function renderTerminal(report: ScanReport): string {
  const lines: string[] = [];

  lines.push(pc.bold(`\n◆ MCPVeil v${report.mcpveilVersion} — scan report`));
  lines.push(pc.dim(`target: ${describeTarget(report.target)}`));
  lines.push(pc.dim(`server: ${report.serverInfo?.name ?? "unknown"} ${report.serverInfo?.version ?? ""}`));
  lines.push(pc.dim(`inventory: ${report.inventorySizes.tools} tools · ${report.inventorySizes.resources} resources · ${report.inventorySizes.prompts} prompts · ${report.durationMs}ms\n`));

  const table = new Table({
    head: ["Severity", "Check", "Tool/Resource", "Finding"],
    style: { head: ["bold"] },
  });
  for (const f of report.findings) {
    const color = SEV_COLOR[f.severity] ?? ((s: string) => s);
    table.push([
      color(f.severity.toUpperCase()),
      f.checkId,
      f.tool ?? f.resource ?? "-",
      f.title,
    ]);
  }
  if (report.findings.length === 0) {
    lines.push(pc.green("✔ No findings. Server passed all enabled checks.\n"));
  } else {
    lines.push(table.toString(), "");
  }

  // per-check rollup with invocation counts
  const roll = new Table({ head: ["Check", "Invocations", "Findings", "Errors", "Skipped"], style: { head: ["bold"] } });
  for (const r of report.results) {
    roll.push([r.meta.id, String(r.invocations), String(r.findings.length), String(r.errors.length), r.skipped ?? "-"]);
  }
  lines.push(roll.toString());

  const gradeColor = report.score.grade === "A" ? pc.green : report.score.grade === "F" ? pc.red : pc.yellow;
  lines.push(`\nPosture score: ${gradeColor(pc.bold(String(report.score.value)))}/100 (grade ${gradeColor(pc.bold(report.score.grade))})`);
  lines.push("");
  return lines.join("\n");
}

function describeTarget(t: ScanReport["target"]): string {
  return t.kind === "stdio" ? `stdio: ${t.command?.join(" ")}` : `${t.kind}: ${t.url}`;
}
