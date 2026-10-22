import { flattenProperties } from "../engine/schema.js";
import type { ScanContext } from "../engine/scanner.js";
import { analyze } from "../engine/analyzer.js";
import { SECRET_PATTERNS } from "../payloads/secretPatterns.js";
import { SECRET_FILE_PROBES } from "../payloads/traversal.js";
import { planCalls, benignValue } from "../engine/argPlanner.js";
import { mask, excerpt } from "../utils/mask.js";
import { fingerprint } from "../engine/analyzer.js";

const REMEDIATION =
  "Load secrets from a managed secret store (env/injector) instead of files inside the server working tree; never echo environment variables or file contents through tools; scrub outputs of token-shaped strings; scope file access to an explicit allowlist.";

export async function runCredentialLeak(ctx: ScanContext): Promise<void> {
  const { session, inv, config } = ctx;

  // 1) static: descriptions + resource contents (always runs, even --inventory-only)
  for (const tool of inv.tools) {
    scanText(ctx, { tool: tool.name, kind: "tool description" }, tool.description);
    for (const p of flattenProperties(tool.properties)) {
      if (p.description) scanText(ctx, { tool: tool.name, kind: `argument '${p.name}' description` }, p.description);
    }
  }
  if (inv.instructions) scanText(ctx, { kind: "server instructions" }, inv.instructions);
  for (const resource of inv.resources) {
    if (resource.description) scanText(ctx, { resource: resource.uri, kind: "resource description" }, resource.description);
  }
  for (const prompt of inv.prompts) {
    if (prompt.description) scanText(ctx, { kind: `prompt '${prompt.name}' description` }, prompt.description);
    if (ctx.active) {
      const args = Object.fromEntries((prompt.arguments ?? []).filter((arg) => arg.required).map((arg) => [arg.name, "mcpveil"]));
      const response = await ctx.getPrompt("credential-leak", prompt.name, args);
      if (response.ok) scanText(ctx, { kind: `prompt '${prompt.name}' content` }, response.text);
    }
  }
  if (ctx.active) {
    for (const res of inv.resources) {
      const r = await ctx.readResource("credential-leak", res.uri);
      if (r.ok && r.text) scanText(ctx, { resource: res.uri, kind: "resource content" }, r.text);
    }
  }

  // 2) active: probe path-like tools with well-known secret file paths
  if (ctx.active) {
    for (const tool of inv.tools) {
      const calls = planCalls(tool, "path", SECRET_FILE_PROBES, config.maxCallsPerTool);
      for (const call of calls) {
        const outcome = await ctx.invokeTool("credential-leak", tool.name, call.args);
          if (!outcome.ok || !outcome.text) continue;
        scanText(ctx, {
          tool: tool.name,
          kind: `response to probe '${call.value}'`,
          payload: call.value,
        }, outcome.text);
      }
    }
    // 3) Tools without injectable fields still expose response surfaces.
    //    Use one schema-aware benign call ({} for zero-argument tools).
    for (const tool of inv.tools) {
      if (planCalls(tool, "path", SECRET_FILE_PROBES, 1).length || flattenProperties(tool.properties).some((p) => p.type === "unknown" || (p.type === "array" && !p.items))) continue;
      const outcome = await ctx.invokeTool("credential-leak", tool.name, Object.fromEntries(tool.properties.filter((p) => p.required).map((p) => [p.name, benignValue(p)])));
      if (!outcome.ok || !outcome.text) continue;
      scanText(ctx, { tool: tool.name, kind: "response (benign invocation)" }, outcome.text);
    }
  }
}

interface ScanSource { tool?: string; resource?: string; kind: string; payload?: string }

function scanText(ctx: ScanContext, source: ScanSource, text: string): void {
  if (!text) return;
  const matchedRanges: [number, number][] = [];
  for (const sp of SECRET_PATTERNS) {
    const m = text.match(sp.regex);
    if (!m) continue;
    const captured = sp.group && m[sp.group] ? m[sp.group] : m[0];
    const start = (m.index ?? 0) + m[0].indexOf(captured);
    const end = start + captured.length;
    if (matchedRanges.some(([a, b]) => start < b && end > a)) continue;
    matchedRanges.push([start, end]);
    ctx.emit({
      checkId: "credential-leak",
      tool: source.tool,
      resource: source.resource,
      payload: source.payload ?? sp.id,
      evidence: `${source.kind}: ${sp.name} → ${mask(captured)} ${excerpt(text, m.index ?? 0, 40)}`,
      severity: sp.severity,
      confidence: "confirmed",
      title: `Potential secret exposed via ${source.kind}${source.tool ? ` (tool '${source.tool}')` : ""}${source.resource ? ` (${source.resource})` : ""}: ${sp.name}`,
      remediation: REMEDIATION,
      fingerprint: fingerprint(["credential-leak", source.tool, source.resource, sp.id, source.payload]),
    });
  }
}
