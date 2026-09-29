export const FORGE_CMD_MARKER = "MCPF0RGE_EXEC_7Q2K";

/**
 * Command injection payloads. Each tries to produce a deterministic, harmless
 * marker in stdout so the analyzer can confirm execution without destructive ops.
 *
 * Design rule (echo-safety): every payload contains the literal text `echo <MARKER>`,
 * so a server that merely ECHOES the argument back never trips the success signal.
 * The signal regex only fires when MARKER appears WITHOUT `echo ` immediately
 * before it — i.e. when the marker was actually produced by a shell.
 */
export interface InjectionPayload {
  arg: string;
  kind: "command" | "sql";
  note: string;
}

export const COMMAND_INJECTION_PAYLOADS: InjectionPayload[] = [
  { arg: "`echo ${M}`", kind: "command", note: "backtick substitution (executes even inside double quotes)" },
  { arg: "$(echo ${M})", kind: "command", note: "dollar-paren substitution (executes even inside double quotes)" },
  { arg: "; echo ${M}", kind: "command", note: "semicolon chain (unquoted concat)" },
  { arg: "&& echo ${M}", kind: "command", note: "and chain" },
  { arg: "| echo ${M}", kind: "command", note: "pipe" },
  { arg: "\necho ${M}", kind: "command", note: "newline injection" },
  { arg: "true; echo ${M}", kind: "command", note: "direct-exec style (payload IS the command)" },
  { arg: "true && echo ${M}", kind: "command", note: "direct-exec and-chain" },
];

/** Expand the ${M} placeholder in every payload. */
export function commandPayloadArgs(): string[] {
  return COMMAND_INJECTION_PAYLOADS.map((p) => p.arg.replace(/\$\{M\}/g, FORGE_CMD_MARKER));
}

/**
 * Success signals for command injection.
 * The lookbehind suppresses raw-argument echoes: if the response contains the
 * payload verbatim, MARKER is always preceded by `echo ` there, and we must not
 * flag a server that simply reflects its input. A server that EXECUTED the
 * payload prints MARKER on its own (preceded by anything other than `echo `).
 */
export const COMMAND_SIGNALS = [
  new RegExp(`(?<!echo )${FORGE_CMD_MARKER}`),
  /uid=\d+\([^)]*\)\s+gid=\d+/, // classic `id` output
];

export const SQL_INJECTION_PAYLOADS: InjectionPayload[] = [
  { arg: "' OR '1'='1", kind: "sql", note: "tautology - all rows" },
  { arg: "1' OR '1'='1' --", kind: "sql", note: "comment-out tautology" },
  { arg: "'; DROP TABLE mcpveil_probe; --", kind: "sql", note: "stacked statement (detect via engine error)" },
  { arg: "' UNION SELECT NULL, NULL --", kind: "sql", note: "union probe" },
  { arg: "\"; ", kind: "sql", note: "quote-break error probe" },
  { arg: "'", kind: "sql", note: "single quote error probe" },
];

/** DB error fingerprints by engine. */
export const SQL_ERROR_SIGNALS: RegExp[] = [
  /SQLITE_ERROR|SQLITE_CONSTRAINT/i,
  /syntax error at or near/i,               // PostgreSQL
  /unterminated quoted string|quoted string not properly ended/i, // pg / oracle
  /you have an error in your sql syntax/i,  // MySQL
  /ORA-\d{5}/i,                             // Oracle
  /unclosed quotation mark after the character string/i, // MSSQL
  /near ".*?": syntax error/i,              // SQLite raw message
];

/** Tautology confirmation: server returned MORE rows than the benign probe. */
export const SQL_ROW_BLAST = /"rows"\s*:\s*(\d+)/i;
