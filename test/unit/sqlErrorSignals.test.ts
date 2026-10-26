// Locks the engine-specific SQL error fingerprints. A hit here raises a
// `suspicious` SQL-injection finding, so every fingerprint needs a realistic
// positive sample and a look-alike negative that must stay silent.
import { describe, it, expect } from "vitest";
import { SQL_ERROR_SIGNALS } from "../../src/payloads/injection.js";

const matchesAny = (text: string): boolean => SQL_ERROR_SIGNALS.some((rx) => rx.test(text));

const engines: { engine: string; positive: string; negative: string }[] = [
  {
    engine: "MariaDB",
    positive:
      "You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''' at line 1",
    negative: "MariaDB server version support is documented in the compatibility matrix.",
  },
  {
    engine: "CockroachDB pgerror",
    positive: 'ERROR: unimplemented: unsupported comparison operator: <string> = <int>',
    negative: "unimplemented: tracked as a follow-up in the roadmap.",
  },
  {
    engine: "CockroachDB parser",
    positive: "invalid syntax: statement ignored: at or near \"'\": syntax error",
    negative: "invalid syntax highlighting was reported by the editor plugin.",
  },
  {
    engine: "Firebird / InterBase",
    positive: "Dynamic SQL Error SQL error code = -104 Token unknown - line 1, column 8",
    negative: "Dynamic SQL generation lives in the query builder module.",
  },
  {
    engine: "Firebird token detail",
    positive: "Token unknown - line 2, column 14",
    negative: "Token unknown handling is covered by the parser tests.",
  },
  {
    engine: "IBM Db2",
    positive: "DB2 SQL Error: SQLCODE=-104, SQLSTATE=42601, SQLERRMC=END-OF-STATEMENT",
    negative: "SQLCODE=-104 is documented without a SQLSTATE in the migration notes.",
  },
  {
    engine: "Trino / Presto",
    positive:
      "Query failed (#20260101_120000_00001_abcde): SYNTAX_ERROR: line 1:8: mismatched input '''. Expecting: <expression>",
    negative: "SYNTAX_ERROR prefixes are documented for Trino failures, not a live error.",
  },
  {
    engine: "Trino / Presto parser detail",
    positive: "line 3:15: mismatched input ';'. Expecting: <EOF>",
    negative: "Config loaded from line 3:15: rows before the retry budget resets.",
  },
];

describe("engine-specific SQL error fingerprints", () => {
  for (const { engine, positive, negative } of engines) {
    it(`detects the ${engine} error shape`, () => {
      expect(matchesAny(positive), `${engine} sample was not detected`).toBe(true);
    });

    it(`stays quiet on the ${engine} look-alike`, () => {
      expect(matchesAny(negative), `${engine} look-alike produced a false positive`).toBe(false);
    });
  }

  it("does not flag ordinary tool output", () => {
    const benign = [
      "Found 3 rows matching 'mcpveil_no_match'.",
      "The query returned no results; try a broader term.",
      "Docs: see the SQL manual for supported server versions.",
      "Execution finished in 12ms with exit code 0.",
    ];
    for (const text of benign) {
      expect(matchesAny(text), `falsely matched: ${text}`).toBe(false);
    }
  });

  it("keeps fingerprints deterministic across repeated evaluation", () => {
    const sample = engines[0]!.positive;
    const first = SQL_ERROR_SIGNALS.map((rx) => rx.test(sample));
    const second = SQL_ERROR_SIGNALS.map((rx) => rx.test(sample));
    expect(second).toEqual(first);
  });
});
