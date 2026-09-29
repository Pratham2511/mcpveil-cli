/**
 * Shared hardened server builder — used by the stdio fixture (index.ts) and
 * the HTTP fixture (../http-server/index.ts).
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { readFileSync } from "node:fs";
import { resolve, sep } from "node:path";
import { createSandbox } from "../sandbox/seed.js";

export function buildSafeServer(): McpServer {
  const sandbox = createSandbox();
  const server = new McpServer({ name: "mcpveil-safe", version: "0.1.0" });

  function isInsideBase(base: string, candidate: string): boolean {
    const rel = resolve(base, candidate);
    return rel === base || rel.startsWith(base + sep);
  }

  server.tool(
    "read_notes",
    "Read a note by name from the notes directory.",
    { name: z.string().describe("note file name") },
    async ({ name }) => {
      if (name.includes("..") || name.includes("/") || name.includes("\\")) {
        return { content: [{ type: "text", text: "Invalid note name." }], isError: true };
      }
      const base = resolve(sandbox.notesDir);
      const target = resolve(base, name);
      if (!isInsideBase(base, target)) {
        return { content: [{ type: "text", text: "Access denied." }], isError: true };
      }
      try {
        return { content: [{ type: "text", text: readFileSync(target, "utf8") }] };
      } catch {
        return { content: [{ type: "text", text: "Note not found." }], isError: true };
      }
    }
  );

  server.tool(
    "run_stats",
    "Runs one of the predefined statistics routines.",
    { routine: z.enum(["summary", "uptime"]) },
    async ({ routine }) => ({
      content: [{ type: "text", text: routine === "summary" ? "requests: 0" : "uptime: 1h" }],
    })
  );

  server.tool(
    "search_users",
    "Search users by exact name.",
    { name: z.string().describe("exact user name") },
    async ({ name }) => {
      const users = [{ id: 1, name: "alice", email: "alice@example.com" }];
      const hits = users.filter((u) => u.name === name);
      return { content: [{ type: "text", text: JSON.stringify({ rows: hits.length, results: hits }) }] };
    }
  );

  server.tool(
    "fetch_docs",
    "Fetch documentation from an allowlisted host.",
    { url: z.string().describe("https://docs.mcpveil.dev/...") },
    async ({ url }) => {
      const allowedHost = "docs.mcpveil.dev";
      let parsed: URL;
      try { parsed = new URL(url); } catch { return { content: [{ type: "text", text: "Invalid URL." }], isError: true }; }
      if (parsed.protocol !== "https:" || parsed.hostname !== allowedHost) {
        return { content: [{ type: "text", text: "Blocked: host not allowlisted." }], isError: true };
      }
      return { content: [{ type: "text", text: "docs placeholder" }] };
    }
  );

  server.tool(
    "get_weather",
    "Get current weather for a city.",
    { city: z.string().describe("city name") },
    async ({ city }) => ({ content: [{ type: "text", text: `Weather in ${city}: 22°C, clear skies` }] })
  );

  return server;
}
