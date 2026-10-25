export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type CheckId =
  | "path-traversal"
  | "command-injection"
  | "sql-injection"
  | "ssrf"
  | "credential-leak"
  | "prompt-injection"
  | "transport-security";

export type TransportKind = "stdio" | "streamable-http" | "sse";

export interface ScanTarget {
  kind: TransportKind;
  /** stdio: full command line, e.g. ["node", "dist/server.js"] */
  command?: string[];
  /** http/sse base URL */
  url?: string;
  /** extra env for stdio spawn */
  env?: Record<string, string>;
  /** Explicitly forward these environment variables. Other credentials are not inherited. */
  inheritEnv?: string[];
  /** HTTP credentials are resolved at connection time, never stored in reports. */
  bearerEnv?: string;
  headerEnv?: Record<string, string>;
  headers?: Record<string, string>;
  authPolicy?: "required" | "public";
  auditOrigin?: boolean;
  protocolMode?: "legacy" | "auto" | "2026-07-28";
}

export interface ToolSchemaProperty {
  name: string;
  type: string; // "string" | "number" | "boolean" | "array" | "object" | "unknown"
  description?: string;
  required: boolean;
  enum?: unknown[];
  constValue?: unknown;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  minItems?: number;
  maxItems?: number;
  /** Unsupported constraints are surfaced as coverage limits, never evaluated as code. */
  limitations?: string[];
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
  schemaLimitations?: string[];
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
  prompts: { name: string; description?: string; arguments?: { name: string; required?: boolean }[] }[];
  serverInfo?: { name?: string; version?: string };
  protocolEra?: "legacy" | "modern";
  instructions?: string;
  errors?: string[];
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
  baselineState?: "accepted" | "new";
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
  errors: string[];         // check-level failures; every probe of a check failing is escalated here
  skipped?: string;         // reason if check did not run
  limitations?: string[];
  resourceReads?: number;
  /** Probes (tool calls, resource reads, prompt gets) that failed at the transport layer without invalidating the check. */
  probeFailures?: number;
  accessProbes?: { name: string; outcome: "accepted" | "rejected" | "unverified" }[];
}

export interface ScanReport {
  schemaVersion: "2.0";
  status: "complete" | "partial" | "failed";
  mode: "active" | "inventory";
  errors: string[];
  coverage: {
    excludedTools: string[];
    untestedTools: string[];
    limitations: string[];
    toolCalls: Record<string, number>;
    /** Failed probes per tool name / resource URI / prompt label. Partial failure does not change scan status. */
    probeFailures: Record<string, number>;
    resourceReads: number;
    latencyMs?: { samples: number; p50: number; p95: number };
  };
  target: ScanTarget;
  serverInfo?: { name?: string; version?: string };
  protocolEra?: "legacy" | "modern";
  startedAt: string;
  durationMs: number;
  inventorySizes: { tools: number; resources: number; prompts: number };
  results: CheckResult[];
  findings: Finding[];
  /** No security grade is assigned to incomplete or metadata-only assessments. */
  score: { value: number; grade: "A" | "B" | "C" | "D" | "F" } | null;
  mcpveilVersion: string;
  policy?: { baseline?: { accepted: number; total: number }; drift?: { added: string[]; removed: string[]; changed: string[] } };
}

export interface ForgeConfig {
  checks: Partial<Record<CheckId, boolean>>;
  failOn: Severity | "never";
  timeoutMs: number;
  scanTimeoutMs: number;
  maxCallsPerTool: number;
  allowTools: string[];          // never touched by active pass
  ssrfCollaboratorUrl?: string;  // optional out-of-band callback base
  output: { format: "terminal" | "json" | "sarif"; path?: string };
}
