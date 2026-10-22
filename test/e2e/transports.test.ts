import { beforeAll, afterAll, it, expect } from "vitest";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { join } from "node:path";
import type { ScanReport } from "../../src/types.js";

let server: ChildProcess;
const runtime = process.env.MCPVEIL_TEST_NODE || process.execPath;
beforeAll(async () => {
  server = spawn(runtime, ["--import", "tsx", "test/http-server/index.ts"], { cwd: process.cwd(), stdio: ["ignore", "ignore", "pipe"] });
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("HTTP fixture startup timed out")), 15000);
    server.on("error", (error) => { clearTimeout(timer); reject(error); });
    server.on("exit", (code) => { clearTimeout(timer); reject(new Error(`HTTP fixture exited: ${code}`)); });
    server.stderr!.on("data", (chunk) => {
      if (String(chunk).includes("listening on")) { clearTimeout(timer); resolve(); }
    });
  });
});
afterAll(async () => {
  if (!server || server.exitCode !== null) return;
  server.kill("SIGTERM");
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => { server.kill("SIGKILL"); resolve(); }, 2000);
    server.once("exit", () => { clearTimeout(timer); resolve(); });
  });
});

it.each([
  ["streamable HTTP", "/mcp", "streamable-http"],
  ["legacy SSE", "/sse", "sse"],
  ["automatic fallback", "/sse", undefined],
])("scans a safe local server over %s", (_name, path, transport) => {
  const args = [join(process.cwd(), "dist/cli.js"), "scan", "--url", `http://127.0.0.1:8123${path}`, "--yes", "--format", "json"];
  if (transport) args.push("--transport", transport);
  const result = spawnSync(runtime, args, { encoding: "utf8", timeout: 30000 });
  expect(result.status, result.stderr).toBe(0);
  const report = JSON.parse(result.stdout) as ScanReport;
  expect(report.status).toBe("complete");
  expect(report.findings).toHaveLength(0);
  expect(report.score?.grade).toBe("A");
  expect(report.serverInfo?.name).toBe("mcpveil-safe");
});
