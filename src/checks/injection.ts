import type { ScanContext } from "../engine/scanner.js";
import { planCalls } from "../engine/argPlanner.js";
import { callToolSafe } from "../engine/executor.js";
import { analyze, verboseErrorFinding, fingerprint } from "../engine/analyzer.js";
import {
  COMMAND_INJECTION_PAYLOADS, commandPayloadArgs, COMMAND_SIGNALS,
  SQL_INJECTION_PAYLOADS, SQL_ERROR_SIGNALS,
} from "../payloads/injection.js";

const CMD_REMEDIATION =
  "Never pass user input to shell interpreters. Use execFile/spawn without a shell, validate against strict allowlists, and prefer library-native operations over shelling out.";

const SQL_REMEDIATION =
  "Use parameterized queries / prepared statements for every query containing user input; reject string-concatenated SQL; least-privilege the DB user.";

export async function runCommandInjection(ctx: ScanContext): Promise<void> {
  const { inv, config } = ctx;
  const payloadValues = commandPayloadArgs();

  for (const tool of inv.tools) {
    const calls = planCalls(tool, "command", payloadValues, config.maxCallsPerTool);
    for (const call of calls) {
      const outcome = await callToolSafe(ctx.session.client, tool.name, call.args, config.timeoutMs);
      ctx.countInvocation("command-injection");
      if (outcome.error) { ctx.registerError("command-injection", `${tool.name}: ${outcome.error}`); continue; }

      const f = analyze({
        checkId: "command-injection", tool: tool.name,
        payload: call.args[call.attacked[0]!] as string,
        responseText: outcome.text,
        signals: COMMAND_SIGNALS,
        severity: "critical",
        title: `OS command injection confirmed in tool '${tool.name}' (argument '${call.attacked[0]}')`,
        remediation: CMD_REMEDIATION,
      });
      if (f) ctx.emit(f);
    }
  }
}

export async function runSqlInjection(ctx: ScanContext): Promise<void> {
  const { inv, config } = ctx;
  const payloadValues = SQL_INJECTION_PAYLOADS.map((p) => p.arg);

  for (const tool of inv.tools) {
    const calls = planCalls(tool, "sql", payloadValues, config.maxCallsPerTool);
    if (calls.length === 0) continue;

    // baseline: benign call to compare row counts for tautology detection
    const benignArgs: Record<string, unknown> = {};
    for (const p of tool.properties) benignArgs[p.name] = benignOf(p);
    const benign = await callToolSafe(ctx.session.client, tool.name, benignArgs, config.timeoutMs);
    const benignRows = extractRows(benign.structured ?? benign.text);

    for (const call of calls) {
      const outcome = await callToolSafe(ctx.session.client, tool.name, call.args, config.timeoutMs);
      ctx.countInvocation("sql-injection");
      if (outcome.error) { ctx.registerError("sql-injection", `${tool.name}: ${outcome.error}`); continue; }

      const f = analyze({
        checkId: "sql-injection", tool: tool.name,
        payload: call.args[call.attacked[0]!] as string,
        responseText: outcome.text,
        signals: SQL_ERROR_SIGNALS,
        severity: "high",
        confidence: "suspicious", // error text alone is suggestive, row blast confirms
        title: `SQL injection indicators in tool '${tool.name}' (argument '${call.attacked[0]}')`,
        remediation: SQL_REMEDIATION,
      });
      if (f) ctx.emit(f);

      const rows = extractRows(outcome.structured ?? outcome.text);
      const payload = call.args[call.attacked[0]!] as string;
      if (benign.ok && outcome.ok && benignRows >= 0 && rows > benignRows) {
        ctx.emit({
          checkId: "sql-injection",
          tool: tool.name,
          payload,
          evidence: `tautology returned ${rows} rows vs ${benignRows} for benign input`,
          severity: "critical",
          confidence: "confirmed",
          title: `SQL injection (tautology row-blast) confirmed in tool '${tool.name}'`,
          remediation: SQL_REMEDIATION,
          fingerprint: fingerprint(["sql-injection", tool.name, payload, "row-blast"]),
        });
      }

      // SQLi handlers that crash may leak stacks — worth an info note.
      const verr = outcome.isError
        ? verboseErrorFinding("sql-injection", tool.name, payload, outcome.text)
        : null;
      if (verr) ctx.emit(verr);
    }
  }
}

function extractRows(structuredOrText: unknown): number {
  if (typeof structuredOrText === "string") {
    const m = structuredOrText.match(/"rows"\s*:\s*(\d+)/);
    return m ? parseInt(m[1], 10) : -1;
  }
  const s = structuredOrText as { rows?: unknown; results?: unknown[]; users?: unknown[]; items?: unknown[] } | null;
  if (s && typeof s === "object") {
    if (typeof s.rows === "number") return s.rows;
    if (Array.isArray(s.results)) return s.results.length;
    if (Array.isArray(s.users)) return s.users.length;
    if (Array.isArray(s.items)) return s.items.length;
  }
  return -1;
}

function benignOf(p: { type: string; enum?: string[] }): unknown {
  if (p.enum?.length) return p.enum[0];
  if (p.type === "number" || p.type === "integer") return 1;
  if (p.type === "boolean") return false;
  if (p.type === "string") return "mcpveil";
  return null;
}
