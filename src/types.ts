export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type CheckId =
  | "path-traversal"
  | "command-injection"
  | "sql-injection"
  | "ssrf"
  | "credential-leak"
  | "prompt-injection";

export type TransportKind = "stdio" | "streamable-http" | "sse";

export interface ScanTarget {
  kind: TransportKind;
  /** stdio: full command line, e.g. ["node", "dist/server.js"] */
  command?: string[];
  /** http/sse base URL */
  url?: string;
  /** extra env for stdio spawn */
  env?: Record<string, string>;
}

export interface ToolSchemaProperty {
  name: string;
  type: string; // "string" | "number" | "boolean" | "array" | "object" | "unknown"
  description?: string;
  required: boolean;
  enum?: string[];
  /** arrays only: parsed JSON-schema of the item type */
  items?: ToolSchemaProperty;
  /** objects only: nested property list */
  properties?: ToolSchemaProperty[];
}

export interface ToolInfo {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  properties: ToolSchemaProperty[];
  requiredArgNames: string[];
}

export interface ResourceInfo {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

export interface Inventory {
  tools: ToolInfo[];
  resources: ResourceInfo[];
  prompts: { name: string; description?: string }[];
  serverInfo?: { name?: string; version?: string };
}

export interface Finding {
  checkId: CheckId;
  tool?: string;            // tool name (active) or undefined (server-level/static)
  resource?: string;        // resource URI (static resource findings)
  payload?: string;         // the payload / pattern that triggered
  evidence: string;         // masked excerpt proving the issue
  severity: Severity;
  confidence: "confirmed" | "suspicious";
  title: string;
  remediation: string;
  /** stable hash for baseline suppression: sha256(checkId|tool|payload|resource) */
  fingerprint: string;
}

export interface CheckMeta {
  id: CheckId;
  title: string;
  description: string;
  /** whether this check actively invokes tools */
  active: boolean;
  defaultSeverity: Severity;
}

export interface CheckResult {
  meta: CheckMeta;
  findings: Finding[];
  invocations: number;      // tool calls made (0 for static)
  errors: string[];         // transport/timeout errors encountered (non-fatal)
  skipped?: string;         // reason if check did not run
}

export interface ScanReport {
  target: ScanTarget;
  serverInfo?: { name?: string; version?: string };
  startedAt: string;
  durationMs: number;
  inventorySizes: { tools: number; resources: number; prompts: number };
  results: CheckResult[];
  findings: Finding[];
  score: { value: number; grade: "A" | "B" | "C" | "D" | "F" };
  mcpveilVersion: string;
}

export interface ForgeConfig {
  checks: Partial<Record<CheckId, boolean>>;
  failOn: Severity | "never";
  timeoutMs: number;
  maxCallsPerTool: number;
  allowTools: string[];          // never touched by active pass
  ssrfCollaboratorUrl?: string;  // optional out-of-band callback base
  output: { format: "terminal" | "json" | "sarif"; path?: string };
}
