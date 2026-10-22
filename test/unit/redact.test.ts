import { it, expect } from "vitest";
import { redactText, redactValue, redactCommand, registerSecrets, redactingStream } from "../../src/utils/redact.js";

it("redacts every token in an excerpt and nested report", () => {
  const token = "ghp_" + "Z".repeat(36);
  expect(redactText(`first ${token} second ${token}`)).not.toContain(token);
  expect(JSON.stringify(redactValue({ messages: [{ text: token }], authorization: "opaque" }))).not.toContain("opaque");
});
it("masks sensitive command flags with separate or assigned values", () => {
  expect(redactCommand(["node", "app.js", "--api-token", "opaque-value", "--password=other-value"]))
    .toEqual(["node", "app.js", "--api-token", "[REDACTED]", "--password=[REDACTED]"]);
});
it("keeps registered credentials scoped to their connection", () => {
  const release = registerSecrets(["opaque-connection-credential"]);
  expect(redactText("opaque-connection-credential")).toBe("[REDACTED]");
  release(); release();
  expect(redactText("opaque-connection-credential")).toBe("opaque-connection-credential");
});
it("redacts credentials split across target stderr chunks", async () => {
  let output = "";
  const stream = redactingStream((text) => { output += text; });
  stream.write("ghp_"); stream.write("Z".repeat(20)); stream.end("Z".repeat(16) + "\n");
  await new Promise<void>((resolve, reject) => { stream.on("finish", resolve); stream.on("error", reject); });
  expect(output).not.toContain("Z".repeat(36));
});
it("redacts encoded credential query names and tokens separated by terminal controls", () => {
  expect(redactText("https://example.invalid/?%74oken=opaque-sensitive-value")).not.toContain("opaque-sensitive-value");
  expect(redactText("ghp_\u001b[31m" + "Z".repeat(36))).not.toContain("Z".repeat(36));
});
it("preserves numeric tool-call counts when a tool name contains secret", () => {
  expect(redactValue({ toolCalls: { dump_secrets: 3, get_token: 2 } })).toEqual({ toolCalls: { dump_secrets: 3, get_token: 2 } });
});
it("masks opaque credentials in JSON excerpts", () => {
  expect(redactText('{"accessToken":"opaque-private-value","safe":"public"}')).not.toContain("opaque-private-value");
});

it("keeps ordinary security prose readable while masking assigned credentials", () => {
  expect(redactText("Secret Exposure and tool-level authorization and OAuth")).toBe("Secret Exposure and tool-level authorization and OAuth");
  expect(redactText("password=opaque-sensitive-value --token other-sensitive-value")).not.toMatch(/opaque-sensitive-value|other-sensitive-value/);
});
