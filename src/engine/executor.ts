import type { Client } from "@modelcontextprotocol/client";
import { ProtocolError, ProtocolErrorCode, type CallToolResult } from "@modelcontextprotocol/client";

export interface ToolCallOutcome {
  ok: boolean;
  isError: boolean;
  text: string;
  structured?: unknown;
  durationMs: number;
  error?: string;
  skipped?: string;
  truncated?: boolean;
}

export interface ReadOutcome { ok: boolean; text: string; error?: string; skipped?: string; truncated?: boolean; rejected?: boolean }
const MAX_CAPTURE_CHARS = 20_000;

function failure(err: unknown): string { return err instanceof Error ? err.message : String(err); }

export async function callToolSafe(
  client: Client, name: string, args: Record<string, unknown>, timeoutMs: number, signal?: AbortSignal,
): Promise<ToolCallOutcome> {
  const started = Date.now();
  try {
    const result = await client.request({ method: "tools/call", params: { name, arguments: args } }, { timeout: timeoutMs, signal }) as CallToolResult;
    const parts: string[] = [];
    for (const block of result.content) {
      if (block.type === "text") parts.push(block.text);
      else if (block.type === "resource") {
        if ("text" in block.resource) parts.push(block.resource.text);
        else parts.push(`[blob ${block.resource.uri}]`);
      }
    }
    if (result.structuredContent !== undefined) parts.push(JSON.stringify(result.structuredContent));
    const text = parts.join("\n");
    return {
      ok: true, isError: Boolean(result.isError), text: text.slice(0, MAX_CAPTURE_CHARS),
      structured: result.structuredContent, durationMs: Date.now() - started,
      truncated: text.length > MAX_CAPTURE_CHARS,
    };
  } catch (err) {
    if (err instanceof ProtocolError && err.code === ProtocolErrorCode.InvalidParams) {
      return { ok: true, isError: true, text: failure(err), durationMs: Date.now() - started };
    }
    return { ok: false, isError: false, text: "", durationMs: Date.now() - started, error: failure(err) };
  }
}

export async function readResourceSafe(
  client: Client, uri: string, timeoutMs: number, signal?: AbortSignal,
): Promise<ReadOutcome> {
  try {
    const result = await client.readResource({ uri }, { timeout: timeoutMs, signal });
    const text = result.contents.map((content) => "text" in content ? content.text : `[blob ${content.uri}]`).join("\n");
    return { ok: true, text: text.slice(0, MAX_CAPTURE_CHARS), truncated: text.length > MAX_CAPTURE_CHARS };
  } catch (err) { return { ok: false, text: "", error: failure(err), rejected: err instanceof ProtocolError && [ProtocolErrorCode.InvalidParams, -32002].includes(err.code) }; }
}

export async function getPromptSafe(
  client: Client, name: string, args: Record<string, string>, timeoutMs: number, signal?: AbortSignal,
): Promise<ReadOutcome> {
  try {
    const result = await client.getPrompt({ name, arguments: args }, { timeout: timeoutMs, signal });
    const text = result.messages.map(({ content }) => {
      if (content.type === "text") return content.text;
      if (content.type === "resource" && "text" in content.resource) return content.resource.text;
      return "";
    }).join("\n");
    return { ok: true, text: text.slice(0, MAX_CAPTURE_CHARS), truncated: text.length > MAX_CAPTURE_CHARS };
  } catch (err) { return { ok: false, text: "", error: failure(err), rejected: err instanceof ProtocolError && [ProtocolErrorCode.InvalidParams, -32002].includes(err.code) }; }
}
