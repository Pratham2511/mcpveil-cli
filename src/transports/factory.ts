import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import type { ScanTarget } from "../types.js";
import { VERSION } from "../version.js";

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

export async function connect(target: ScanTarget): Promise<ForgeSession> {
  if (target.kind === "stdio") {
    if (!target.command?.length) throw new Error("stdio target requires a command");
    const client = newClient();
    const transport = new StdioClientTransport({
      command: target.command[0],
      args: target.command.slice(1),
      env: buildEnv(target.env),
    });
    await client.connect(transport);
    return { client, close: () => client.close() };
  }

  const url = new URL(target.url!);

  if (target.kind === "streamable-http") {
    const client = newClient();
    try {
      const transport = new StreamableHTTPClientTransport(url);
      await client.connect(transport);
      return { client, close: () => client.close() };
    } catch {
      // per spec, fall back to SSE if streamable HTTP is unsupported;
      // a fresh client avoids reusing a half-open session.
      await client.close().catch(() => {});
    }
  }

  const sseClient = newClient();
  const sse = new SSEClientTransport(url);
  await sseClient.connect(sse);
  return { client: sseClient, close: () => sseClient.close() };
}

function buildEnv(extra: Record<string, string> | undefined): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined) env[k] = v;
  }
  return { ...env, ...(extra ?? {}) };
}
