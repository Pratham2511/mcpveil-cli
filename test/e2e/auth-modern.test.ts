import { beforeAll, afterAll, it, expect } from "vitest";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { join } from "node:path";
let server: ChildProcess; let port: number;
const runtime = process.env.MCPVEIL_TEST_NODE || process.execPath;
const cli = join(process.cwd(), "dist/cli.js");
beforeAll(async () => {
  server = spawn(runtime, ["test/fixtures/modern-server.mjs", "http"], { stdio: ["ignore", "ignore", "pipe"] });
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("modern HTTP startup timed out")), 10000);
    server.on("error", reject);
    server.stderr!.on("data", (chunk) => { const match = /PORT=(\d+)/.exec(String(chunk)); if (match) { port = Number(match[1]); clearTimeout(timer); resolve(); } });
  });
});
afterAll(async () => { server.kill(); await new Promise<void>((resolve) => { const timer = setTimeout(() => { server.kill("SIGKILL"); resolve(); }, 2000); server.once("exit", () => { clearTimeout(timer); resolve(); }); }); });
function scan(path: string, extra: string[] = [], auth = false) {
  const result = spawnSync(runtime, [cli, "scan", "--url", `http://127.0.0.1:${port}${path}`, "--protocol", "2026-07-28", "--timeout", "1000", "--scan-timeout", "10000", "--yes", "--format", "json",
    ...(auth ? ["--bearer-env", "MCPVEIL_AUTH_FIXTURE", "--header-env", "X-Test-Key=MCPVEIL_HEADER_FIXTURE"] : []), ...extra],
    { encoding: "utf8", timeout: 15000, env: { ...process.env, MCPVEIL_AUTH_FIXTURE: "synthetic-auth-fixture-only", MCPVEIL_HEADER_FIXTURE: "synthetic-header-fixture-only" } });
  if (result.error) throw result.error;
  expect(result.stdout, result.stderr).not.toBe("");
  return { ...result, report: JSON.parse(result.stdout), all: result.stdout + result.stderr };
}
it("scans a real modern-only stdio server using pinned and automatic negotiation", () => {
  for (const mode of ["2026-07-28", "auto"]) {
    const result = spawnSync(runtime, [cli, "scan", "--stdio", `${JSON.stringify(runtime)} test/fixtures/modern-server.mjs stdio`, "--protocol", mode, "--yes", "--format", "json"], { encoding: "utf8", timeout: 15000 });
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout).protocolEra).toBe("modern");
  }
});
it("uses supplied bearer/custom headers, confirms rejection policies, and reports modern era", () => {
  const result = scan("/protected", ["--auth-policy", "required", "--check-origin"], true);
  expect(result.status, result.all).toBe(0);
  expect(result.report.protocolEra).toBe("modern");
  expect(result.report.status).toBe("complete");
  expect(result.report.findings).toEqual([]);
  expect(result.report.results.find((r: any) => r.meta.id === "transport-security").accessProbes.map((p: any) => p.outcome)).toEqual(["rejected", "rejected", "rejected"]);
  expect(result.all).not.toContain("synthetic-auth-fixture-only");
  expect(result.all).not.toContain("synthetic-header-fixture-only");
});
it("rejects unauthenticated requests without downgrading protocols/transports", () => {
  const result = scan("/protected");
  expect(result.status).toBe(2); expect(result.report.status).toBe("failed");
  expect(result.report.errors.join(" ")).toContain("401");
});
it("flags a required-auth policy bypass while intentionally public endpoints stay clean", () => {
  const bypass = scan("/public", ["--auth-policy", "required"]);
  expect(bypass.status, bypass.all).toBe(1);
  expect(bypass.report.findings.filter((f: any) => f.checkId === "transport-security")).toHaveLength(2);
  expect(scan("/public", ["--auth-policy", "public"]).status).toBe(0);
});
it("flags an accepted untrusted Origin only when the check is explicitly requested", () => {
  expect(scan("/origin-open").status).toBe(0);
  const result = scan("/origin-open", ["--check-origin"]);
  expect(result.status, result.all).toBe(1);
  expect(result.report.findings.some((f: any) => f.payload === "origin")).toBe(true);
});
it("detects and masks an opaque supplied credential echoed by the server", () => {
  const result = scan("/echo", [], true);
  expect(result.status, result.all).toBe(1);
  expect(result.report.findings.some((f: any) => f.checkId === "credential-leak")).toBe(true);
  expect(result.all).not.toContain("synthetic-auth-fixture-only");
});
it("blocks cross-origin redirects without sending any request to the sink", async () => {
  expect(scan("/redirect", [], true).status).toBe(2);
  expect((await (await fetch(`http://127.0.0.1:${port}/stats`)).json()).sinkHits).toBe(0);
});
it("bounds oversized HTTP bodies and reports server failures rather than fallback success", () => {
  expect(scan("/huge").status).toBe(2);
  expect(scan("/server-error").status).toBe(2);
});
