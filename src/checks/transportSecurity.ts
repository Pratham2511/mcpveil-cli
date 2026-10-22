import type { ScanContext } from "../engine/scanner.js";
import { connect } from "../transports/factory.js";
import { resolveHeaders } from "../transports/http.js";
import { fingerprint } from "../engine/analyzer.js";
export async function runTransportSecurity(ctx: ScanContext): Promise<void> {
  if (!ctx.active || ctx.target.kind === "stdio") return;
  const emit = (probe: string, evidence: string) => ctx.emit({ checkId: "transport-security", payload: probe, evidence, severity: "high", confidence: "confirmed",
    title: probe === "origin" ? "Untrusted Origin accepted by MCP endpoint" : "Required authentication policy bypassed", remediation: probe === "origin"
      ? "Validate Origin on MCP HTTP requests against an explicit allowlist, including rejecting Origin: null."
      : "Require valid credentials before completing the MCP handshake/discovery. Enforce per-tool authorization separately.", fingerprint: fingerprint(["transport-security", probe]) });
  const probe = async (name: string, headers: Record<string, string>) => {
    let session;
    const result = ctx.results.get("transport-security")!;
    result.accessProbes ??= [];
    try {
      session = await connect({ ...ctx.target, headers, bearerEnv: undefined, headerEnv: undefined }, { timeoutMs: ctx.config.timeoutMs, signal: ctx.signal });
      result.accessProbes.push({ name, outcome: "accepted" });
      emit(name, `${name} probe completed MCP connection/discovery when policy required rejection. No tool was invoked by this access probe.`);
    } catch (err) {
      const status = (err as { status?: number }).status;
      result.accessProbes.push({ name, outcome: [401, 403].includes(status ?? 0) ? "rejected" : "unverified" });
      if (![401, 403].includes(status ?? 0)) ctx.limit("transport-security", `${name} probe could not establish an access-control verdict: ${err instanceof Error ? err.message : String(err)}`);
    } finally { await session?.close().catch(() => {}); }
  };
  if (ctx.target.authPolicy === "required") {
    await probe("anonymous", {});
    const original = resolveHeaders(ctx.target);
    await probe("invalid-credentials", Object.fromEntries([...original.keys()].map((name) => [name, "mcpveil-invalid-test-credential"])));
  }
  if (ctx.target.auditOrigin) {
    await probe("origin", { ...Object.fromEntries(resolveHeaders(ctx.target)), Origin: "https://untrusted.example.invalid" });
  }
}
