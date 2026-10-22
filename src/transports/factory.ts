import { scopedFetch, resolveHeaders, validateEndpoint } from "./http.js";
import { SdkHttpError } from "@modelcontextprotocol/client";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { SSEClientTransport } from "@modelcontextprotocol/client";
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

function newClient(target: ScanTarget): Client {
  return new Client(
    { name: FORGE_CLIENT_NAME, version: FORGE_CLIENT_VERSION },
    { capabilities: {}, inputRequired: { autoFulfill: false }, listMaxPages: 32,
      versionNegotiation: { mode: target.protocolMode === "2026-07-28" ? { pin: "2026-07-28" } : target.protocolMode ?? "legacy", probe: { timeoutMs: 1500, maxRetries: 0 } } }
  );
}

export async function connect(target: ScanTarget, opts: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<ForgeSession> {
  const options = { timeout: opts.timeoutMs ?? 10000, signal: opts.signal };
  if (target.kind === "stdio") {
    if (!target.command?.length) throw new Error("stdio target requires a command");
    const client = newClient(target);
    const home = mkdtempSync(join(tmpdir(), "mcpveil-target-home-"));
    const env = buildEnv(target.env, target.inheritEnv, home);
    const release = registerSecrets([...commandSecrets(target.command), ...Object.values(target.env ?? {}), ...(target.inheritEnv ?? []).map((key) => process.env[key] ?? "")]);
    const transport = new StdioClientTransport({
      command: target.command[0],
      args: target.command.slice(1),
      env, stderr: "pipe", maxBufferSize: 2 * 1024 * 1024,
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
  const headers = resolveHeaders(target);
  validateEndpoint(url, [...headers].length > 0);
  const release = registerSecrets([...headers.values()].flatMap((value) => [value, value.replace(/^(Bearer|Basic)\s+/i, "")]));
  const scoped = scopedFetch(url, headers, opts.signal);
  let unsupportedStatus: number | undefined;
  let accessStatus: number | undefined;
  const httpFetch: typeof scoped = async (input, init) => {
    try { const response = await scoped(input, init);
      if ([404, 405, 501].includes(response.status)) unsupportedStatus = response.status;
      return response; }
    catch (err) { if ([401, 403].includes((err as { status?: number }).status ?? 0)) accessStatus = (err as { status: number }).status; throw err; }
  };
  let connected: Client | undefined;
  const close = async () => { try { await connected?.close(); } finally { release(); } };
  try {
    if (target.kind === "streamable-http") {
      const client = newClient(target);
      try {
        const transport = new StreamableHTTPClientTransport(url, { fetch: httpFetch, requestInit: { redirect: "error" } });
        await client.connect(transport, options);
        connected = client;
        return { client, close };
      } catch (err) {
        await client.close().catch(() => {});
        // Legacy SSE fallback is only appropriate for unsupported HTTP methods/endpoints.
        if (!([404, 405, 501].includes(err instanceof SdkHttpError ? err.status ?? 0 : unsupportedStatus ?? 0)) || target.protocolMode === "2026-07-28") throw err;
      }
    }
    const client = newClient({ ...target, protocolMode: "legacy" });
    connected = client;
    const sse = new SSEClientTransport(url, { fetch: httpFetch, requestInit: { redirect: "error" }, eventSourceInit: { fetch: httpFetch } });
    await client.connect(sse, options);
    return { client, close };
  } catch (err) {
    const error = Object.assign(new Error(redactText(err instanceof Error ? err.message : String(err))), { status: accessStatus ?? (err as { status?: number }).status });
    await close().catch(() => {});
    throw error;
  }
}

function buildEnv(extra: Record<string, string> | undefined, inherit: string[] = [], home: string): Record<string, string> {
  const env: Record<string, string> = { HOME: home, USERPROFILE: home };
  for (const key of ["PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ", ...inherit]) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  return { ...env, ...(extra ?? {}) };
}
