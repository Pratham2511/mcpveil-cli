// test/unit/sarif.test.ts
import { it, expect } from "vitest";
import { renderSarif } from "../../src/report/sarif.js";
import type { ScanReport, Finding } from "../../src/types.js";
import { fingerprint } from "../../src/engine/analyzer.js";

const finding: Finding = {
  checkId: "path-traversal",
  tool: "read_file",
  payload: "../canary.txt",
  evidence: "MCPF0RGE_CANARY_9F3A_TRAVERSAL_CONFIRMED",
  severity: "high",
  confidence: "confirmed",
  title: "Path traversal confirmed",
  remediation: "Contain paths.",
  fingerprint: fingerprint(["path-traversal", "read_file", "p"]),
};

const report = {
  target: { kind: "stdio", command: ["node", "server.js"] },
  startedAt: new Date().toISOString(),
  durationMs: 5,
  inventorySizes: { tools: 1, resources: 0, prompts: 0 },
  results: [
    {
      meta: {
        id: "path-traversal",
        title: "Path Traversal / Arbitrary File Read",
        description: "d",
        active: true,
        defaultSeverity: "high" as const,
      },
      findings: [finding],
      invocations: 3,
      errors: [],
    },
  ],
  findings: [finding],
  score: { value: 80, grade: "B" as const },
  mcpveilVersion: "0.1.0",
} as unknown as ScanReport;

it("produces parseable SARIF 2.1.0", () => {
  const sarif = JSON.parse(renderSarif(report));
  expect(sarif.version).toBe("2.1.0");
  expect(sarif.runs[0].tool.driver.name).toBe("MCPVeil");
});

it("maps every finding to a rule with a location", () => {
  const sarif = JSON.parse(renderSarif(report));
  expect(sarif.runs[0].results).toHaveLength(1);
  expect(sarif.runs[0].results[0].ruleId).toBe("MCPF/path-traversal");
  expect(sarif.runs[0].results[0].level).toBe("error"); // high → error
  expect(sarif.runs[0].tool.driver.rules[0].id).toBe("MCPF/path-traversal");
  expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe("mcp://tool/read_file");
});

it("carries the mcpveil fingerprint for baseline suppression", () => {
  const sarif = JSON.parse(renderSarif(report));
  expect(sarif.runs[0].results[0].properties.fingerprint).toBe(finding.fingerprint);
});
