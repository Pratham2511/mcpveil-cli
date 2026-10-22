import type { ScanContext } from "../engine/scanner.js";
import { planCalls } from "../engine/argPlanner.js";
import { analyze } from "../engine/analyzer.js";
import { SSRF_PAYLOADS } from "../payloads/ssrf.js";

const REMEDIATION =
  "Validate outbound URLs against an allowlist of schemes and hosts; resolve DNS and block private/link-local ranges (127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1, fc00::/7); reject file://, gopher:// and other non-HTTP schemes; disable redirect following or re-validate each hop.";

export async function runSsrf(ctx: ScanContext): Promise<void> {
  if (!ctx.active) return;
  const { inv, config } = ctx;
  const payloads = [...SSRF_PAYLOADS];
  if (config.ssrfCollaboratorUrl) {
    ctx.limit("ssrf", "Blind collaborator callbacks are not verified; no out-of-band SSRF assurance is assigned");
  }

  for (const tool of inv.tools) {
    const calls = planCalls(tool, "url", payloads.map((p) => p.url), config.maxCallsPerTool);
    for (const call of calls) {
      const value = call.args[call.attacked[0]!] as string;
      const match = payloads.find((p) => p.url === value);
      if (!match) continue;

      const outcome = await ctx.invokeTool("ssrf", tool.name, call.args);
      if (!outcome.ok) continue;

      const f = analyze({
        checkId: "ssrf", tool: tool.name, payload: value,
        responseText: outcome.text,
        signals: match.signals,
        severity: match.category === "metadata" ? "critical" : "high",
        title: `SSRF confirmed via tool '${tool.name}' (${match.category} target reachable: ${value})`,
        remediation: REMEDIATION,
      });
      if (f) ctx.emit(f);
    }
  }
}
