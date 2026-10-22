import type { FetchLike } from "@modelcontextprotocol/client";
import type { ScanTarget } from "../types.js";
export function resolveHeaders(target: ScanTarget): Headers {
  const headers = new Headers();
  const set = (name: string, value: string) => {
    try { headers.set(name, value); }
    catch { throw new Error("invalid HTTP header name or value (value omitted)"); }
  };
  const blocked = /^(host|connection|content-length|transfer-encoding|mcp-.*|accept|content-type)$/i;
  for (const [name, value] of Object.entries(target.headers ?? {})) {
    if (blocked.test(name)) throw new Error(`reserved HTTP header: ${name}`);
    set(name, value);
  }
  const read = (key: string) => {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || !process.env[key]) throw new Error("HTTP credential variable unavailable or invalid; check the environment variable name");
    return process.env[key]!;
  };
  for (const [name, env] of Object.entries(target.headerEnv ?? {})) {
    if (blocked.test(name)) throw new Error(`reserved HTTP header: ${name}`);
    set(name, read(env));
  }
  if (target.bearerEnv) {
    if (headers.has("authorization")) throw new Error("configure bearer or Authorization header, not both");
    set("authorization", `Bearer ${read(target.bearerEnv)}`);
  }
  return headers;
}
export function validateEndpoint(url: URL, authenticated = false): void {
  if (!["https:", "http:"].includes(url.protocol) || url.username || url.password) throw new Error("target must be an HTTP(S) URL without embedded credentials");
  if (authenticated && url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
    throw new Error("HTTP credentials require HTTPS (loopback test servers are allowed)");
}
/** Deny redirects and cross-origin SSE endpoints before sending any credential. */
export function scopedFetch(endpoint: URL, headers: Headers, signal?: AbortSignal, implementation: FetchLike = fetch): FetchLike {
  validateEndpoint(endpoint, [...headers].length > 0);
  return async (input, init = {}) => {
    const url = new URL(String(input), endpoint);
    if (url.origin !== endpoint.origin || url.username || url.password) throw new Error("cross-origin MCP request blocked");
    const merged = new Headers(init.headers);
    for (const [name, value] of headers) merged.set(name, value);
    const response = await implementation(url, { ...init, headers: merged, redirect: "manual", signal: signal ? AbortSignal.any([signal, ...(init.signal ? [init.signal] : [])]) : init.signal });
    if (response.status >= 300 && response.status < 400) { await response.body?.cancel(); throw new Error("MCP HTTP redirect blocked; configure the final endpoint URL explicitly"); }
    if ([401, 403].includes(response.status)) {
      await response.body?.cancel();
      throw Object.assign(new Error(`MCP endpoint rejected access (HTTP ${response.status})`), { status: response.status });
    }
    // Limit decoded bytes, including chunked bodies and compressed responses.
    const max = 2 * 1024 * 1024;
    if (Number(response.headers.get("content-length")) > max) { await response.body?.cancel(); throw new Error("MCP HTTP response exceeds 2 MiB limit"); }
    if (!response.body) return response;
    let bytes = 0;
    const body = response.body.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({ transform(chunk, controller) {
      bytes += chunk.byteLength;
      if (bytes > max) throw new Error("MCP HTTP response exceeds 2 MiB limit");
      controller.enqueue(chunk);
    } }));
    return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
  };
}
