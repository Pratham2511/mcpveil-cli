import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { Inventory, ToolInfo, ToolSchemaProperty } from "../types.js";

import { parseSchema } from "./schema.js";

export async function inventory(client: Client, opts: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<Inventory> {
  const options = { timeout: opts.timeoutMs ?? 10000, signal: opts.signal };
  const capabilities = client.getServerCapabilities();
  const errors: string[] = [];
  const seen = new Set<string>();
  const guardCursor = (kind: string, cursor: string | undefined, count: number) => {
    if (count > 1000 || seen.size > 100) throw new Error(`${kind} inventory exceeds bounded page/item limit`);
    if (cursor && seen.has(`${kind}:${cursor}`)) throw new Error(`${kind} inventory repeats a pagination cursor`);
    if (cursor) seen.add(`${kind}:${cursor}`);
  };
  const tools: ToolInfo[] = [];
  let cursor: string | undefined;
  if (capabilities?.tools) do {
    guardCursor("tools", cursor, tools.length);
    const res = await client.listTools(cursor ? { cursor } : undefined, options);
    for (const t of res.tools) {
      const parsed = parseSchema((t.inputSchema ?? {}) as Record<string, unknown>);
      tools.push({
        name: t.name,
        description: t.description ?? "",
        inputSchema: (t.inputSchema ?? {}) as Record<string, unknown>,
        properties: parsed.properties, schemaLimitations: parsed.limitations,
        requiredArgNames: ((t.inputSchema as any)?.required as string[]) ?? [],
      });
    }
    cursor = res.nextCursor;
  } while (cursor);

  const resources: Inventory["resources"] = [];
  if (capabilities?.resources) try {
    let rc: string | undefined;
    do {
      guardCursor("resources", rc, resources.length);
      const res = await client.listResources(rc ? { cursor: rc } : undefined, options);
      for (const r of res.resources) {
        resources.push({ uri: r.uri, name: r.name, description: r.description, mimeType: r.mimeType });
      }
      rc = res.nextCursor;
    } while (rc);
  } catch (err) {
    errors.push(`resources inventory failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  const prompts: Inventory["prompts"] = [];
  if (capabilities?.prompts) try {
    let pc: string | undefined;
    do {
      guardCursor("prompts", pc, prompts.length);
      const res = await client.listPrompts(pc ? { cursor: pc } : undefined, options);
      for (const p of res.prompts) prompts.push({ name: p.name, description: p.description, arguments: p.arguments });
      pc = res.nextCursor;
    } while (pc);
  } catch (err) {
    errors.push(`prompts inventory failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  return { tools, resources, prompts, errors, serverInfo: client.getServerVersion(), instructions: client.getInstructions() };
}
