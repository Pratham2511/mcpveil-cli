import type { ScanContext } from "../engine/scanner.js";
import { planCalls, benignValue } from "../engine/argPlanner.js";
import { analyze, verboseErrorFinding, fingerprint } from "../engine/analyzer.js";
import { commandPayloadArgs, COMMAND_SIGNALS, SQL_INJECTION_PAYLOADS, SQL_ERROR_SIGNALS } from "../payloads/injection.js";

const CMD_REMEDIATION = "Use execFile/spawn without a shell, strict argument allowlists, or library-native operations. Never interpolate untrusted input into shell commands.";
const SQL_REMEDIATION = "Use parameterized queries or prepared statements and a least-privileged database account. Never concatenate input into SQL.";

export async function runCommandInjection(ctx: ScanContext): Promise<void> {
  if (!ctx.active) return;
  for (const tool of ctx.inv.tools) {
    for (const call of planCalls(tool, "command", commandPayloadArgs(), ctx.config.maxCallsPerTool)) {
      const outcome = await ctx.invokeTool("command-injection", tool.name, call.args);
      if (!outcome.ok) continue;
      const finding = analyze({
        checkId: "command-injection", tool: tool.name, payload: JSON.stringify(call.args),
        responseText: outcome.text, signals: COMMAND_SIGNALS, severity: "critical",
        title: `Decoded command marker returned by '${tool.name}'`, remediation: CMD_REMEDIATION,
      });
      if (finding) ctx.emit(finding);
    }
  }
}

export async function runSqlInjection(ctx: ScanContext): Promise<void> {
  if (!ctx.active) return;
  for (const tool of ctx.inv.tools) {
    const calls = planCalls(tool, "sql", SQL_INJECTION_PAYLOADS.map((payload) => payload.arg), ctx.config.maxCallsPerTool);
    if (!calls.length) continue;
    // Baseline matches probe shape: required args only, so a server that
    // rejects optional-argument combinations cannot skew the row comparison.
    const benignArgs = Object.fromEntries(tool.properties.filter((property) => property.required).map((property) => [property.name, benignValue(property)]));
    const benign = await ctx.invokeTool("sql-injection", tool.name, benignArgs);
    const benignRows = extractRows(benign.structured ?? benign.text);
    const outcomes = new Map<string, { rows: number; ok: boolean; echoed: boolean }>();
    for (const call of calls) {
      const outcome = await ctx.invokeTool("sql-injection", tool.name, call.args);
      if (!outcome.ok) continue;
      const payload = JSON.stringify(call.args);
      const value = call.value;
      outcomes.set(`${call.placement ?? call.attacked[0]}:${value}`, {
        rows: extractRows(outcome.structured ?? outcome.text), ok: !outcome.isError,
        echoed: typeof value === "string" && outcome.text.includes(value),
      });
      const finding = analyze({
        checkId: "sql-injection", tool: tool.name, payload, responseText: outcome.text,
        signals: SQL_ERROR_SIGNALS, severity: "high", confidence: "suspicious",
        title: `SQL error indicators in '${tool.name}'`, remediation: SQL_REMEDIATION,
      });
      if (finding) ctx.emit(finding);
      if (outcome.isError) {
        const verbose = verboseErrorFinding("sql-injection", tool.name, payload, outcome.text);
        if (verbose) ctx.emit(verbose);
      }
    }
    const trueInput = SQL_INJECTION_PAYLOADS[0]!.arg;
    const falseInput = SQL_INJECTION_PAYLOADS[1]!.arg;
    for (const [key, positive] of outcomes) {
      if (!key.endsWith(`:${trueInput}`)) continue;
      const negative = outcomes.get(key.slice(0, -trueInput.length) + falseInput);
      if (benign.ok && positive.ok && negative?.ok && !positive.echoed && benignRows >= 0 &&
          positive.rows > benignRows && positive.rows > negative.rows && negative.rows === benignRows) {
        ctx.emit({
          checkId: "sql-injection", tool: tool.name, payload: trueInput,
          evidence: `Paired read-only probes: true condition ${positive.rows} rows; false condition ${negative.rows}; benign ${benignRows}`,
          severity: "critical", confidence: "confirmed", title: `SQL boolean differential confirmed in '${tool.name}'`,
          remediation: SQL_REMEDIATION, fingerprint: fingerprint(["sql-injection", tool.name, key, "boolean-differential"]),
        });
      }
    }
  }
}

function extractRows(value: unknown): number {
  if (typeof value === "string") {
    try { return extractRows(JSON.parse(value)); } catch { return -1; }
  }
  if (value && typeof value === "object") {
    const data = value as Record<string, unknown>;
    if (typeof data.rows === "number" && Number.isFinite(data.rows) && data.rows >= 0) return data.rows;
    for (const key of ["results", "users", "items"]) if (Array.isArray(data[key])) return data[key].length;
  }
  return -1;
}
