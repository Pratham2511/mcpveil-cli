export const FORGE_CMD_MARKER = "MCPF0RGE_EXEC_7Q2K";

/**
 * Read-only POSIX probes encode the marker as octal bytes. Reflecting or
 * normalizing the input cannot produce the decoded marker as an output line.
 */
export interface InjectionPayload {
  arg: string;
  kind: "command" | "sql";
  note: string;
}

export const COMMAND_INJECTION_PAYLOADS: InjectionPayload[] = [
  { arg: "`${M}`", kind: "command", note: "backtick substitution" },
  { arg: "$(${M})", kind: "command", note: "dollar-paren substitution" },
  { arg: "; ${M}", kind: "command", note: "semicolon chain" },
  { arg: "&& ${M}", kind: "command", note: "and chain" },
  { arg: "| ${M}", kind: "command", note: "pipe" },
  { arg: "\n${M}", kind: "command", note: "newline injection" },
  { arg: "true; ${M}", kind: "command", note: "direct command" },
  { arg: "true && ${M}", kind: "command", note: "direct and-chain" },
];

/** Expand the ${M} placeholder in every payload. */
export function commandPayloadArgs(): string[] {
  const encoded = [...FORGE_CMD_MARKER].map((char) => `\\${char.charCodeAt(0).toString(8)}`).join("");
  const command = `printf '\\n${encoded}\\n'`;
  return COMMAND_INJECTION_PAYLOADS.map((p) => p.arg.replace(/\$\{M\}/g, () => command));
}

/**
 * Success signals for command injection.
 * The lookbehind suppresses raw-argument echoes: if the response contains the
 * payload verbatim, MARKER is always preceded by `echo ` there, and we must not
 * flag a server that simply reflects its input. A server that EXECUTED the
 * payload prints MARKER on its own (preceded by anything other than `echo `).
 */
export const COMMAND_SIGNALS = [new RegExp(`^${FORGE_CMD_MARKER}\\r?$`, "m")];

export const SQL_INJECTION_PAYLOADS: InjectionPayload[] = [
  { arg: "mcpveil_no_match' OR '1'='1' --", kind: "sql", note: "paired true condition" },
  { arg: "mcpveil_no_match' AND '1'='2' --", kind: "sql", note: "paired false condition" },
  { arg: "'; SELECT 1; --", kind: "sql", note: "read-only stacked statement" },
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
