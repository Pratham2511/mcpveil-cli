import { it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import qs from "qs";
import { Hono } from "hono";
import { serveStatic } from "hono/serve-static";

it("qs serializes comma arrays with non-callable toString values without crashing", () => {
  const input = JSON.parse('{"items":[{"toString":null}]}');
  expect(() => qs.stringify(input, { arrayFormat: "comma" })).not.toThrow();
  expect(qs.stringify({ items: ["one", "two"] }, { arrayFormat: "comma" })).toBe("items=one%2Ctwo");
});

it("ip-address rejects a long malformed zone without blocking the process", () => {
  // Bound this in a child: the vulnerable regex would stall the test runner.
  const result = spawnSync(process.execPath, ["-e", `
    const { Address6 } = require('ip-address');
    process.exit(Address6.isValid('%'.repeat(200_000) + '\\n') ? 1 : 0);
  `], { cwd: process.cwd(), encoding: "utf8", timeout: 3_000 });
  expect(result.error, result.stderr).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
});

it("Hono static serving cannot decode an encoded path past protected middleware", async () => {
  const app = new Hono();
  app.use("/private/*", (c) => c.text("Access denied", 403));
  app.use("*", serveStatic({
    getContent: async (path) => path.replace(/^\.?\//, "") === "private/secret.txt"
      ? new Response("PRIVATE_FILE_CONTENT") : null,
  }));

  expect((await app.request("http://localhost/private/secret.txt")).status).toBe(403);
  for (const path of ["/%7%30rivate/secret.txt", "/pr%6%39vate/secret.txt"]) {
    const response = await app.request(`http://localhost${path}`);
    expect(await response.text()).not.toContain("PRIVATE_FILE_CONTENT");
  }
});
