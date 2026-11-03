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
  const values = COMMAND_INJECTION_PAYLOADS.map((p) => p.arg.replace(/\$\{M\}/g, () => command));
  // Quote breakout + encoded Node marker also exercises cmd.exe-backed Node targets.
  // Reflection retains only base64 bytes, never the decoded success line.
  const base64 = Buffer.from(FORGE_CMD_MARKER).toString("base64");
  values.push(`" & node -e "console.log(Buffer.from('${base64}','base64').toString())" & rem "`);
  return values;
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
  // MariaDB phrases the 1064 syntax error differently from MySQL; anchor on
  // the server-name wording so ordinary "check the manual" prose stays clean.
  /check the manual that corresponds to your MariaDB server version/i, // MariaDB
  /ERROR:\s+unimplemented:|invalid syntax: statement ignored/i, // CockroachDB
  /Dynamic SQL Error|Token unknown - line \d+, column \d+/i, // Firebird / InterBase
  /SQLCODE\s*=\s*-\d+,\s*SQLSTATE\s*=\s*[0-9A-Z]{5}/i, // IBM Db2
  /(?:SYNTAX_ERROR|SYNTAX ERROR):\s*line \d+:\d+:/i, // Trino / Presto
  /line \d+:\d+: mismatched input/i,        // Trino / Presto parser detail
];

/** Tautology confirmation: server returned MORE rows than the benign probe. */
export const SQL_ROW_BLAST = /"rows"\s*:\s*(\d+)/i;
