import { it, expect } from "vitest";
import { scopedFetch, validateEndpoint, resolveHeaders } from "../../src/transports/http.js";
it("requires HTTPS for credentials outside loopback and rejects embedded URL credentials", () => {
  expect(() => validateEndpoint(new URL("http://example.invalid/mcp"), true)).toThrow(/HTTPS/);
  expect(() => validateEndpoint(new URL("https://user:password@example.invalid/mcp"))).toThrow(/embedded/);
  expect(() => validateEndpoint(new URL("http://127.0.0.1/mcp"), true)).not.toThrow();
  expect(() => resolveHeaders({ kind: "streamable-http", headers: { Host: "evil.invalid" } })).toThrow(/reserved/);
});
it("never calls fetch for a cross-origin endpoint or follows a same-origin redirect", async () => {
  let calls = 0;
  const f = scopedFetch(new URL("https://example.invalid/mcp"), new Headers({ "X-Api-Key": "synthetic-test-only" }), undefined,
    async (_url, init) => { calls++; expect(init?.redirect).toBe("manual"); return new Response(null, { status: 307, headers: { location: "/other" } }); });
  await expect(f("https://elsewhere.invalid/mcp")).rejects.toThrow(/cross-origin/);
  expect(calls).toBe(0);
  await expect(f("https://example.invalid/mcp")).rejects.toThrow(/redirect/);
  expect(calls).toBe(1);
});
it("bounds decoded chunked HTTP bodies even without a Content-Length header", async () => {
  const f = scopedFetch(new URL("https://example.invalid/mcp"), new Headers(), undefined, async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(2 * 1024 * 1024 + 1)); controller.close(); },
  })));
  const response = await f("https://example.invalid/mcp");
  await expect(response.arrayBuffer()).rejects.toThrow(/2 MiB/);
});
it("rejects missing and conflicting credential sources without contacting a server", () => {
  expect(() => resolveHeaders({ kind: "streamable-http", bearerEnv: "MCPVEIL_INTENTIONALLY_UNSET" })).toThrow(/unavailable/);
  process.env.MCPVEIL_AUTH_POLICY_TEST = "synthetic-value-only";
  try { expect(() => resolveHeaders({ kind: "streamable-http", bearerEnv: "MCPVEIL_AUTH_POLICY_TEST", headers: { Authorization: "synthetic-other" } })).toThrow(/not both/); }
  finally { delete process.env.MCPVEIL_AUTH_POLICY_TEST; }
});
it("does not disclose malformed opaque credential values in validation errors", () => {
  const value = "synthetic-sensitive-header\r\nmalformed";
  try { resolveHeaders({kind:"streamable-http",headers:{"X-Api-Key":value}}); throw new Error("validation did not fail"); }
  catch (error) { expect(String(error)).not.toContain("synthetic-sensitive-header"); expect(String(error)).toContain("value omitted"); }
});
