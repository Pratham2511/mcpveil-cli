import type { ScanContext } from "../engine/scanner.js";
import { INJECTION_PHRASES, INVISIBLE_UNICODE } from "../payloads/secretPatterns.js";
import { excerpt } from "../utils/mask.js";
import { fingerprint } from "../engine/analyzer.js";

const REMEDIATION =
  "Treat tool descriptions as data, not instructions. Remove imperative second-person text aimed at the model, strip invisible/bidi unicode from metadata, and re-hash tools/list output at deploy time to detect rug-pull edits (roadmap check: tool-drift).";

export async function runPromptInjection(ctx: ScanContext): Promise<void> {
  const { inv } = ctx;

  for (const tool of inv.tools) {
    inspect(ctx, { tool: tool.name, kind: "tool description" }, tool.description);
    for (const p of tool.properties) {
      if (p.description) inspect(ctx, { tool: tool.name, kind: `argument '${p.name}' description` }, p.description);
    }
  }
  for (const prompt of inv.prompts) {
    if (prompt.description) inspect(ctx, { tool: undefined, kind: `prompt '${prompt.name}'` }, prompt.description);
    if (ctx.active) {
      const args = Object.fromEntries((prompt.arguments ?? []).filter((arg) => arg.required).map((arg) => [arg.name, "mcpveil"]));
      const response = await ctx.getPrompt("prompt-injection", prompt.name, args);
      if (response.ok) inspect(ctx, { kind: `prompt '${prompt.name}' content` }, response.text);
    }
  }
  if (inv.instructions) inspect(ctx, { kind: "server instructions" }, inv.instructions);
  for (const resource of inv.resources) {
    if (resource.description) inspect(ctx, { kind: `resource '${resource.uri}' description` }, resource.description);
    if (ctx.active) {
      const response = await ctx.readResource("prompt-injection", resource.uri);
      if (response.ok) inspect(ctx, { kind: `resource '${resource.uri}' content` }, response.text);
    }
  }
}

function inspect(ctx: ScanContext, source: { tool?: string; kind: string }, text: string): void {
  if (!text) return;
  for (const rx of INJECTION_PHRASES) {
    const m = text.match(rx);
    if (m) {
      ctx.emit({
        checkId: "prompt-injection",
        tool: source.tool,
        payload: m[0],
        evidence: excerpt(text, m.index ?? 0),
        severity: "medium",
        confidence: "suspicious",
        title: `Instructional/override phrasing in ${source.kind}${source.tool ? ` (tool '${source.tool}')` : ""}`,
        remediation: REMEDIATION,
        fingerprint: fingerprint(["prompt-injection", source.tool, source.kind, m[0]]),
      });
    }
  }
  for (const rx of INVISIBLE_UNICODE) {
    const m = text.match(rx);
    if (m) {
      ctx.emit({
        checkId: "prompt-injection",
        tool: source.tool,
        payload: `U+${m[0].codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}`,
        evidence: excerpt(text, m.index ?? 0),
        severity: "medium",
        confidence: "confirmed",
        title: `Invisible unicode character in ${source.kind}${source.tool ? ` (tool '${source.tool}')` : ""} — common tool-poisoning smuggle channel`,
        remediation: REMEDIATION,
        fingerprint: fingerprint(["prompt-injection", source.tool, source.kind, "invisible-unicode"]),
      });
      break; // one unicode finding per source is enough
    }
  }
}
