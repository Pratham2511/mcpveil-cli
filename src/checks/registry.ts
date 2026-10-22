import { runTransportSecurity } from "./transportSecurity.js";
import type { CheckMeta, CheckId } from "../types.js";
import { runPathTraversal } from "./pathTraversal.js";
import { runCommandInjection, runSqlInjection } from "./injection.js";
import { runSsrf } from "./ssrf.js";
import { runCredentialLeak } from "./credentialLeak.js";
import { runPromptInjection } from "./promptInjection.js";
import type { ScanContext } from "../engine/scanner.js";

export interface CheckRunner {
  meta: CheckMeta;
  run(ctx: ScanContext): Promise<void>; // push into ctx.emit
}

export const PATH_TRAVERSAL_META: CheckMeta = {
  id: "path-traversal",
  title: "Path Traversal / Arbitrary File Read",
  description: "Attempts to escape server-side base directories and read arbitrary files via tool arguments and file:// resources.",
  active: true,
  defaultSeverity: "high",
};

export const COMMAND_INJECTION_META: CheckMeta = {
  id: "command-injection",
  title: "OS Command Injection",
  description: "Injects shell metacharacters with an echo-marker to detect server-side command execution.",
  active: true,
  defaultSeverity: "critical",
};

export const SQL_INJECTION_META: CheckMeta = {
  id: "sql-injection",
  title: "SQL Injection",
  description: "Tautology, stacked-statement, and error-based probes with per-engine error fingerprinting.",
  active: true,
  defaultSeverity: "high",
};

export const SSRF_META: CheckMeta = {
  id: "ssrf",
  title: "Server-Side Request Forgery",
  description: "Probes loopback services, file:// fetches, and cloud metadata endpoints; optional out-of-band collaborator.",
  active: true,
  defaultSeverity: "high",
};

export const CREDENTIAL_LEAK_META: CheckMeta = {
  id: "credential-leak",
  title: "Credential & Secret Exposure",
  description: "Static scan of descriptions/resources plus active reads of well-known secret files (.env, id_rsa, /proc/self/environ).",
  active: true,
  defaultSeverity: "critical",
};

export const PROMPT_INJECTION_META: CheckMeta = {
  id: "prompt-injection",
  title: "Tool Description Poisoning / Hidden Instructions",
  description: "Static detection of instructional injection phrases and invisible unicode in tool/resource metadata.",
  active: true,
  defaultSeverity: "medium",
};

export const CHECKS: CheckRunner[] = [
  { meta: { id: "transport-security", title: "HTTP access policy", description: "Explicit anonymous/invalid-credential and untrusted Origin connection probes; tool-level authorization and OAuth conformance are outside this check.", active: true, defaultSeverity: "high" }, run: runTransportSecurity },
  { meta: PATH_TRAVERSAL_META, run: runPathTraversal },
  { meta: COMMAND_INJECTION_META, run: runCommandInjection },
  { meta: SQL_INJECTION_META, run: runSqlInjection },
  { meta: SSRF_META, run: runSsrf },
  { meta: CREDENTIAL_LEAK_META, run: runCredentialLeak },
  { meta: PROMPT_INJECTION_META, run: runPromptInjection },
];

export function getRunner(id: CheckId): CheckRunner | undefined {
  return CHECKS.find((c) => c.meta.id === id);
}
