import type { ScanContext } from "../engine/scanner.js";
import { planCalls } from "../engine/argPlanner.js";
import { analyze, verboseErrorFinding } from "../engine/analyzer.js";
import { TRAVERSAL_PAYLOADS } from "../payloads/traversal.js";

const REMEDIATION =
  "Resolve user-supplied paths against a fixed base directory, verify the resolved path starts with the base (path.resolve + startsWith / path.relative check), and reject absolute paths, '..' segments, and encoded variants before filesystem access.";

const SIGNALS = [
  /MCPF0RGE_CANARY_9F3A_TRAVERSAL_CONFIRMED/, // our planted canary file
  /root:[x*]:0:0:/,                           // /etc/passwd content
  /\[fonts\]/i,                               // windows/win.ini content
];

export async function runPathTraversal(ctx: ScanContext): Promise<void> {
  if (!ctx.active) return; // inventory-only: no resource reads, no tool calls

  const { session, inv, config } = ctx;

  // 1) resources: try file:// URIs pointing outside the presented root
  for (const res of inv.resources) {
    for (const uri of buildResourceProbes(res.uri)) {
      const r = await ctx.readResource("path-traversal", uri, { probe: true });
      if (!r.ok || !r.text) continue;
      const f = analyze({
        checkId: "path-traversal", resource: uri, payload: uri,
        responseText: r.text,
        signals: SIGNALS,
        severity: "high",
        title: `Resource read escapes intended scope via crafted URI (${res.uri} → ${uri})`,
        remediation: REMEDIATION,
      });
      if (f) ctx.emit(f);
    }
  }

  // 2) tools: schema-aware payload placement
  for (const tool of inv.tools) {
    const values = buildTraversalValues();
    const calls = planCalls(tool, "path", values, config.maxCallsPerTool);
    for (const call of calls) {
      const outcome = await ctx.invokeTool("path-traversal", tool.name, call.args);
      if (!outcome.ok) continue;

      const f = analyze({
        checkId: "path-traversal", tool: tool.name,
        payload: call.args[call.attacked[0]!] as string,
        responseText: outcome.text,
        signals: SIGNALS,
        severity: "high",
        title: `Path traversal confirmed in tool '${tool.name}' (argument '${call.attacked[0]}')`,
        remediation: REMEDIATION,
      });
      if (f) ctx.emit(f);

      const verr = outcome.isError
        ? verboseErrorFinding("path-traversal", tool.name, call.args[call.attacked[0]!] as string, outcome.text)
        : null;
      if (verr) ctx.emit(verr);
    }
  }
}

/**
 * Deterministic, OS-tolerant value list, ordered so the highest-signal
 * payloads land inside any maxCallsPerTool cap:
 *   pass 1 — one payload per template (canary for relative/encoded/windows,
 *            passwd for absolute templates)
 *   pass 2 — two-level canary variants for deeper base-dir layouts
 */
function buildTraversalValues(): string[] {
  const values: string[] = [];
  for (const tpl of TRAVERSAL_PAYLOADS) {
    const absolute = tpl.category === "absolute";
    values.push(tpl.template.replace("{ARG}", absolute ? "passwd" : "canary.txt"));
  }
  for (const tpl of TRAVERSAL_PAYLOADS) {
    values.push(tpl.template.replace("{ARG}", "../canary.txt"));
  }
  return values;
}

function buildResourceProbes(originalUri: string): string[] {
  const probes: string[] = [];
  if (originalUri.startsWith("file://")) {
    // try escaping the presented root
    const dir = originalUri.replace(/^file:\/\//, "").replace(/\/[^/]*$/, "");
    probes.push(`file://${dir}/../canary.txt`);
    probes.push("file:///etc/passwd");
  }
  return probes;
}
