import type { ToolInfo, ToolSchemaProperty } from "../types.js";

export type ArgIntent = "path" | "url" | "command" | "sql" | "neutral";

const PATH_HINTS = /\b(path|file|filename|filepath|dir|directory|folder|read|open|load|doc|document|template|include|import)\b/i;
const URL_HINTS = /\b(url|uri|link|endpoint|host|hostname|domain|fetch|download|target|base_?url)\b/i;
const CMD_HINTS = /\b(cmd|command|exec|execute|shell|sh\b|bash|run|script|spawn|eval|program|binary)\b/i;
const SQL_HINTS = /\b(query|sql|search|filter|where|select|find|lookup|user|username|email|name|q\b|term|keyword)\b/i;

export function classifyArg(p: ToolSchemaProperty): ArgIntent {
  const hay = `${p.name} ${p.description ?? ""}`;
  if (CMD_HINTS.test(hay)) return "command";
  if (URL_HINTS.test(hay)) return "url";
  if (PATH_HINTS.test(hay)) return "path";
  if (SQL_HINTS.test(hay)) return "sql";
  return "neutral";
}

/** Benign filler by JSON-schema type, so required args don't reject the call. */
export function benignValue(p: ToolSchemaProperty): unknown {
  if (p.enum?.length) return p.enum[0];
  switch (p.type) {
    case "number":
    case "integer":
      return 1;
    case "boolean":
      return false;
    case "array":
      // one realistic benign item so strict servers (minItems, required item
      // fields) accept the call — empty arrays get rejected by real servers.
      return p.items ? [benignValue(p.items)] : [];
    case "object":
      // fill only required nested fields so strict servers accept the call
      return benignObject(p);
    case "string":
      return "mcpveil";
    default:
      return null;
  }
}

function benignObject(p: ToolSchemaProperty): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const nested of p.properties ?? []) {
    if (nested.required) out[nested.name] = benignValue(nested);
  }
  return out;
}

export interface PlannedCall {
  tool: ToolInfo;
  args: Record<string, unknown>;
  /** names of args that received an attack payload */
  attacked: string[];
  intent: ArgIntent;
  /** dotted path of where the payload was placed, e.g. "entities[].name" */
  placement?: string;
}

/**
 * Build argument sets for a tool given a payload for a specific intent.
 *
 * Strategy v2 (schema-aware, real-world tested):
 *   1. top-level string args — ranked by intent, payload replaces the value
 *      (unchanged behavior; covers most servers).
 *   2. nested placement — when a tool has NO string args (e.g. memory's
 *      `create_entities(entities: [{name, type, ...}])`) the payload is
 *      planted inside array/object structures by their JSON schema:
 *        array of strings        → [payload]
 *        array of objects        → [{ best-matching field: payload, rest benign }]
 *        object with strings     → { best-matching field: payload, rest benign }
 *   3. every other required arg is filled with a realistic benign value
 *      (one item for arrays, required fields for objects).
 *
 * Deterministic; capped at maxCalls.
 */
export function planCalls(
  tool: ToolInfo,
  intent: ArgIntent,
  payloadValues: string[],
  maxCalls: number
): PlannedCall[] {
  const stringProps = tool.properties.filter((p) => p.type === "string");
  const calls: PlannedCall[] = [];

  if (stringProps.length > 0) {
    // rank args by intent match
    const ranked = [...stringProps].sort((a, b) => rank(classifyArg(b), intent) - rank(classifyArg(a), intent));
    const targets = ranked.filter((p) => rank(classifyArg(p), intent) > 0).slice(0, 2).length
      ? ranked.filter((p) => rank(classifyArg(p), intent) > 0).slice(0, 2)
      : [ranked[0]];

    for (const target of targets) {
      for (const value of payloadValues) {
        if (calls.length >= maxCalls) break;
        const args: Record<string, unknown> = {};
        for (const p of tool.properties) {
          if (p.name === target.name) args[p.name] = value;
          else if (p.required || benignIsSafe(p)) args[p.name] = benignValue(p);
        }
        calls.push({ tool, args, attacked: [target.name], intent: classifyArg(target) });
      }
    }
  }

  // nested placement: structures that carry no top-level string arg
  const structuredProps = tool.properties.filter(
    (p) => (p.type === "array" || p.type === "object") && !stringProps.some((s) => s.name === p.name)
  );
  for (const prop of structuredProps) {
    const nested = planNested(prop, intent);
    for (const placement of nested) {
      for (const value of payloadValues) {
        if (calls.length >= maxCalls) break;
        const args: Record<string, unknown> = {};
        for (const p of tool.properties) {
          if (p.name === prop.name) args[p.name] = placement.build(value);
          else if (p.required || benignIsSafe(p)) args[p.name] = benignValue(p);
        }
        calls.push({
          tool, args, attacked: [prop.name], intent,
          placement: `${prop.name}${placement.path}`,
        });
      }
    }
  }

  return calls.slice(0, maxCalls);
}

interface NestedPlacement {
  /** e.g. "[]" for string arrays, "[].name" for object arrays, ".field" for objects */
  path: string;
  /** build the full argument value for this placement given a payload */
  build: (payload: string) => unknown;
}

/** Enumerate schema-valid payload placements inside one array/object prop. */
function planNested(prop: ToolSchemaProperty, intent: ArgIntent): NestedPlacement[] {
  const placements: NestedPlacement[] = [];

  if (prop.type === "array") {
    const item = prop.items;
    if (!item) return []; // unknown item schema — do not guess
    if (item.type === "string") {
      placements.push({ path: "[]", build: (payload) => [payload] });
    } else if (item.type === "object" && item.properties?.length) {
      for (const field of rankedNestedFields(item, intent)) {
        placements.push({
          path: `[].${field.name}`,
          build: (payload) => [buildNestedObject(item, field.name, payload)],
        });
      }
    } else if (item.type === "object" && (!item.properties || item.properties.length === 0)) {
      // free-form object items: common in real servers (metadata, options)
      placements.push({ path: "[]", build: (payload) => [{ name: payload }] });
    }
    return placements;
  }

  if (prop.type === "object") {
    if (prop.properties?.length) {
      for (const field of rankedNestedFields(prop, intent)) {
        placements.push({
          path: `.${field.name}`,
          build: (payload) => buildNestedObject(prop, field.name, payload),
        });
      }
    } else {
      // free-form object (additionalProperties): one conventional shape
      placements.push({ path: "", build: (payload) => ({ name: payload }) });
    }
    return placements;
  }

  return placements;
}

/** Nested string fields ranked by intent; best match first. */
function rankedNestedFields(obj: ToolSchemaProperty, intent: ArgIntent): ToolSchemaProperty[] {
  const stringFields = (obj.properties ?? []).filter((f) => f.type === "string" && !f.enum);
  if (stringFields.length === 0) return [];
  const ranked = [...stringFields].sort(
    (a, b) => rank(classifyArg(b), intent) - rank(classifyArg(a), intent)
  );
  // payload goes into the best match; two fields max for coverage vs noise
  return ranked.slice(0, 2);
}

/** Build an object item where `field` gets the payload and required siblings get benign values. */
function buildNestedObject(
  obj: ToolSchemaProperty,
  field: string,
  payload: string
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const nested of obj.properties ?? []) {
    if (nested.name === field) out[nested.name] = payload;
    else if (nested.required) out[nested.name] = benignValue(nested);
  }
  // schemas with NO required fields still need at least the payload field
  if (!(field in out)) out[field] = payload;
  return out;
}

function benignIsSafe(p: ToolSchemaProperty): boolean {
  // optional args still get benign values to maximize call realism,
  // except object/array which some servers mishandle — keep them out.
  return p.type === "string" || p.type === "number" || p.type === "boolean" || p.type === "integer";
}

function rank(actual: ArgIntent, wanted: ArgIntent): number {
  if (wanted === "neutral") return actual === "neutral" ? 2 : 1;
  return actual === wanted ? 3 : actual === "neutral" ? 1 : 0;
}
