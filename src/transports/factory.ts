import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import type { ScanTarget } from "../types.js";
import { VERSION } from "../version.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { redactingStream, registerSecrets, redactText, commandSecrets } from "../utils/redact.js";

export const FORGE_CLIENT_NAME = "mcpveil";
export const FORGE_CLIENT_VERSION = VERSION;

export interface ForgeSession {
  client: Client;
  close(): Promise<void>;
}

function newClient(): Client {
  return new Client(
    { name: FORGE_CLIENT_NAME, version: FORGE_CLIENT_VERSION },
    { capabilities: {} }
  );
}

export async function connect(target: ScanTarget, opts: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<ForgeSession> {
  const options = { timeout: opts.timeoutMs ?? 10000, signal: opts.signal };
  if (target.kind === "stdio") {
    if (!target.command?.length) throw new Error("stdio target requires a command");
    const client = newClient();
    const home = mkdtempSync(join(tmpdir(), "mcpveil-target-home-"));
    const env = buildEnv(target.env, target.inheritEnv, home);
    const release = registerSecrets([...commandSecrets(target.command), ...Object.values(target.env ?? {}), ...(target.inheritEnv ?? []).map((key) => process.env[key] ?? "")]);
    const transport = new StdioClientTransport({
      command: target.command[0],
      args: target.command.slice(1),
      env, stderr: "pipe",
    });
    transport.stderr?.pipe(redactingStream((text) => process.stderr.write(text)));
    let closed = false;
    const close = async () => {
      if (closed) return; closed = true;
      try { await client.close(); } finally { release(); rmSync(home, { recursive: true, force: true }); }
    };
    try { await client.connect(transport, options); }
    catch (err) {
      const error = new Error(redactText(err instanceof Error ? err.message : String(err)));
      await close(); throw error;
    }
    return { client, close };
  }

  const url = new URL(target.url!);

  if (target.kind === "streamable-http") {
    const client = newClient();
    try {
      const transport = new StreamableHTTPClientTransport(url);
      await client.connect(transport, options);
      return { client, close: () => client.close() };
    } catch {
      // per spec, fall back to SSE if streamable HTTP is unsupported;
      // a fresh client avoids reusing a half-open session.
      await client.close().catch(() => {});
    }
  }

  const sseClient = newClient();
  const sse = new SSEClientTransport(url);
  try { await sseClient.connect(sse, options); }
  catch (err) { await sseClient.close().catch(() => {}); throw err; }
  return { client: sseClient, close: () => sseClient.close() };
}

function buildEnv(extra: Record<string, string> | undefined, inherit: string[] = [], home: string): Record<string, string> {
  const env: Record<string, string> = { HOME: home, USERPROFILE: home };
  for (const key of ["PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ", ...inherit]) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  return { ...env, ...(extra ?? {}) };
}
