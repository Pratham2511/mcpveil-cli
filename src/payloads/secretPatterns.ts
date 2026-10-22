export interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: "critical" | "high" | "medium";
  /** capture group index used as the masked evidence */
  group?: number;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  { id: "aws-access-key", name: "AWS Access Key ID", regex: /\b(AKIA[0-9A-Z]{16})\b/, severity: "critical", group: 1 },
  { id: "aws-secret", name: "AWS Secret Access Key", regex: /aws.{0,20}["']?([a-z0-9/+=]{40})["']?/i, severity: "critical", group: 1 },
  { id: "github-pat", name: "GitHub PAT", regex: /\b(ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/, severity: "critical", group: 1 },
  { id: "openai", name: "OpenAI API Key", regex: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b/, severity: "critical", group: 1 },
  { id: "anthropic", name: "Anthropic API Key", regex: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/, severity: "critical", group: 1 },
  { id: "slack", name: "Slack Token", regex: /\b(xox[bpars]-[A-Za-z0-9-]{10,})\b/, severity: "high", group: 1 },
  { id: "google", name: "Google API Key", regex: /\b(AIza[0-9A-Za-z_-]{35})\b/, severity: "high", group: 1 },
  { id: "npm", name: "npm token", regex: /\b(npm_[A-Za-z0-9]{36})\b/, severity: "critical", group: 1 },
  { id: "private-key", name: "Private Key Block", regex: /(-----BEGIN [A-Z ]*PRIVATE KEY-----)/, severity: "critical", group: 1 },
  { id: "jwt", name: "JWT", regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b/, severity: "high", group: 1 },
  { id: "basic-auth-url", name: "Credentials in URL", regex: /\bhttps?:\/\/[^/\s:]+:([^/\s@]{8,})@/, severity: "high", group: 1 },
  { id: "env-assignment", name: "Secret-looking env assignment", regex: /\b([A-Z_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)[A-Z_]*)\s*=\s*["']?([^\s"'{};]{8,})/, severity: "medium", group: 2 },
  { id: "db-uri", name: "Database connection URI", regex: /\b(mongodb(?:\+srv)?|postgres|postgresql|mysql|redis):\/\/[^\s'"]{8,}/, severity: "high" },
  { id: "json-secret", name: "Secret-like JSON value", regex: /["'][A-Za-z0-9_-]*(?:password|passwd|secret|token|api[-_]?key|private[-_]?key)[A-Za-z0-9_-]*["']\s*:\s*["']([^"'\\]{8,})["']/i, severity: "medium", group: 1 },
];

/** Hidden/invisible unicode used to smuggle prompt-injection text. */
export const INVISIBLE_UNICODE: RegExp[] = [
  /[\u200B-\u200F]/,   // zero-width chars + bidi marks
  /[\u202A-\u202E]/,   // bidi overrides
  /[\u2060-\u2064]/,   // invisible operators
  /\uFEFF/,            // BOM in middle of string
];

/** Instructional injection phrases inside tool descriptions. */
export const INJECTION_PHRASES: RegExp[] = [
  /ignore (all )?(previous|prior|above) (instructions|prompts|rules)/i,
  /do not (tell|inform|reveal to) the user/i,
  /(system|developer) (prompt|message) (says|requires|overrides)/i,
  /before (using|invoking) this tool, (read|fetch|send|exfiltrate)/i,
  /(send|post|upload|forward).{0,40}(contents|data|credentials|keys).{0,40}(to|at)\s+https?:\/\//i,
  /you (are|'re) now (in )?(dev|developer|admin|god) mode/i,
  /append.{0,30}(to|in).{0,30}(next|your) (response|message)/i,
];
