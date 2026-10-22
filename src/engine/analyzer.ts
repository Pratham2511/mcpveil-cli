import type { Finding, CheckId, Severity } from "../types.js";
import { createHash } from "node:crypto";
import { mask, excerpt } from "../utils/mask.js";

export function fingerprint(parts: (string | undefined)[]): string {
  return createHash("sha256").update(parts.join("|")).digest("hex").slice(0, 16);
}

export interface AnalyzeInput {
  checkId: CheckId;
  tool?: string;
  resource?: string;
  payload?: string;
  responseText: string;
  signals: RegExp[];
  severity: Severity;
  confidence?: "confirmed" | "suspicious";
  title: string;
  remediation: string;
}

export function analyze(i: AnalyzeInput): Finding | null {
  for (const rx of i.signals) {
    const m = i.responseText.match(rx);
    if (m) {
      const idx = m.index ?? 0;
      return {
        checkId: i.checkId,
        tool: i.tool,
        resource: i.resource,
        payload: i.payload,
        evidence: excerpt(i.responseText, idx),
        severity: i.severity,
        confidence: i.confidence ?? "confirmed",
        title: i.title,
        remediation: i.remediation,
        fingerprint: fingerprint([i.checkId, i.tool, i.resource, i.payload, rx.source]),
      };
    }
  }
  return null;
}

/** Error text that leaks server internals is its own low/info-level signal. */
export function verboseErrorFinding(
  checkId: CheckId, tool: string, payload: string | undefined, responseText: string
): Finding | null {
  const rx = /(at .+?\(.+?:\d+:\d+\)|node_modules\/[^\s]+|\/(?:usr|home|var|app)\/[^\s"]+\.(?:ts|js|mjs))/;
  const m = responseText.match(rx);
  if (!m) return null;
  return {
    checkId,
    tool,
    payload,
    evidence: excerpt(responseText, m.index ?? 0),
    severity: "info",
    confidence: "confirmed",
    title: `Verbose error output leaks server internals (${tool})`,
    remediation: "Return sanitized error messages to clients; log full stack traces server-side only.",
    fingerprint: fingerprint([checkId, tool, payload, "verbose-error"]),
  };
}
