// Locks the probe-failure taxonomy: per-probe transport errors are counted,
// not escalated to scan errors, unless every probe of a check (or every probe
// of a tool across all checks) failed. Protocol rejections of prompts are
// coverage skips.
import { describe, it, expect } from "vitest";
import type { Client } from "@modelcontextprotocol/client";
import { ProtocolError, ProtocolErrorCode } from "@modelcontextprotocol/client";
import { runScan } from "../../src/engine/scanner.js";
import type { ForgeSession } from "../../src/transports/factory.js";
import { getPromptSafe } from "../../src/engine/executor.js";
import { defaultConfig, validateConfig } from "../../src/config/loader.js";
import type { ScanTarget } from "../../src/types.js";

const TOOL = {
  name: "lookup",
  description: "Look up literal text in a catalog.",
  inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] },
};
const PROMPT = { name: "greeting", description: "Say hi.", arguments: [{ name: "style", required: true }] };

type ProbeResult = { text: string } | { error: Error };

interface StubShape {
  onCall(name: string, args: Record<string, unknown>): ProbeResult;
  onGetPrompt?(name: string): ProbeResult;
}

function stubSession(shape: StubShape): ForgeSession {
  const client = {
    getServerCapabilities: () => ({ tools: { listChanged: false }, prompts: shape.onGetPrompt ? { listChanged: false } : undefined }),
    getServerVersion: () => ({ name: "stub", version: "0.0.0" }),
    getProtocolEra: () => "legacy",
    getInstructions: () => undefined,
    request: async (message: { method: string; params?: { name?: string; arguments?: Record<string, unknown> } }) => {
      if (message.method === "tools/list") return { tools: [TOOL] };
      if (message.method === "prompts/list") return { prompts: [PROMPT] };
      if (message.method === "tools/call") {
        const outcome = shape.onCall(message.params!.name!, message.params!.arguments ?? {});
        if ("error" in outcome) throw outcome.error;
        return { content: [{ type: "text", text: outcome.text }] };
      }
      throw new Error(`unexpected request: ${message.method}`);
    },
    getPrompt: async (params: { name: string }) => {
      const outcome = shape.onGetPrompt?.(params.name) ?? { text: "hi" };
      if ("error" in outcome) throw outcome.error;
      return { messages: [{ role: "user", content: { type: "text", text: outcome.text } }] };
    },
  } as unknown as Client;
  return { client, close: async () => {} };
}

const TARGET: ScanTarget = { kind: "stdio", command: ["node", "stub-server.js"] };
const CONFIG = validateConfig({ ...defaultConfig(), timeoutMs: 1000, maxCallsPerTool: 128 });

describe("probe-failure taxonomy", () => {
  it("a tool whose every probe errored lands in untestedTools with a partial status", async () => {
    const report = await runScan(stubSession({ onCall: () => ({ error: new Error("transport reset") }) }), TARGET, CONFIG);
    expect(report.coverage.toolCalls.lookup!).toBeGreaterThan(0);
    expect(report.status).toBe("partial");
    expect(report.coverage.untestedTools).toContain("lookup");
    expect(report.coverage.probeFailures.lookup).toBe(report.coverage.toolCalls.lookup);
    expect(report.coverage.limitations).toContain("lookup: every probe failed at the transport layer; the tool response surface is untested");
    expect(report.errors.some((error) => /^path-traversal: all \d+ probes failed$/.test(error))).toBe(true);
    expect(report.results.every((result) => result.invocations === 0 || (result.probeFailures ?? 0) === result.invocations)).toBe(true);
    expect(report.score).toBeNull();
  });

  it("a tool with a single errored probe stays complete, counted, and unlimited", async () => {
    let failures = 0;
    const report = await runScan(stubSession({
      onCall: (_name, args) => args.query === "%2e%2e%2fcanary.txt"
        ? (failures++, { error: new Error("simulated timeout") })
        : { text: `ack: ${String(args.query)}` },
    }), TARGET, CONFIG);
    expect(failures).toBe(1);
    expect(report.status).toBe("complete");
    expect(report.errors).toEqual([]);
    expect(report.coverage.limitations).toEqual([]);
    expect(report.coverage.untestedTools).toEqual([]);
    expect(report.coverage.probeFailures.lookup).toBe(1);
    const traversal = report.results.find((result) => result.meta.id === "path-traversal")!;
    expect(traversal.probeFailures).toBe(1);
    expect(traversal.errors).toEqual([]);
    expect(report.score).not.toBeNull();
  });

  it("prompt protocol rejections are coverage skips, not errors or probe failures", async () => {
    const report = await runScan(stubSession({
      onCall: () => ({ text: "ack" }),
      onGetPrompt: () => ({ error: new ProtocolError(ProtocolErrorCode.InvalidParams, "Unknown arguments") }),
    }), TARGET, CONFIG);
    expect(report.status).toBe("complete");
    expect(report.errors).toEqual([]);
    expect(Object.keys(report.coverage.probeFailures).filter((key) => key.startsWith("prompt "))).toEqual([]);
  });
});

describe("getPromptSafe rejection mapping", () => {
  it("maps protocol validation errors to rejected and transport errors to probe failures", async () => {
    const rejecting = { getPrompt: async () => { throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Unknown prompt"); } } as unknown as Client;
    const rejected = await getPromptSafe(rejecting, "greeting", {}, 1000);
    expect(rejected.ok).toBe(false);
    expect(rejected.rejected).toBe(true);

    const crashing = { getPrompt: async () => { throw new Error("socket hang up"); } } as unknown as Client;
    const transport = await getPromptSafe(crashing, "greeting", {}, 1000);
    expect(transport.rejected).toBeFalsy();
    expect(transport.error).toBe("socket hang up");
  });
});
