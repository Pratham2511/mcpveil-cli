import type { ForgeConfig, Inventory, ScanReport, ScanTarget, CheckResult, Finding, CheckId } from "../types.js";
import type { ForgeSession } from "../transports/factory.js";
import { inventory } from "./inventory.js";
import { callToolSafe, readResourceSafe, getPromptSafe, type ToolCallOutcome, type ReadOutcome } from "./executor.js";
import { CHECKS } from "../checks/registry.js";
import { computeScore } from "../report/score.js";
import { VERSION } from "../version.js";
import { validateConfig } from "../config/loader.js";
import { redactValue, redactCommand } from "../utils/redact.js";
import { log } from "../utils/logger.js";

export interface ScanContext {
  session: ForgeSession;
  inv: Inventory;
  config: ForgeConfig;
  target: ScanTarget;
  active: boolean;
  emit(f: Finding): void;
  results: Map<CheckId, CheckResult>;
  limit(id: CheckId, reason: string): void;
  invokeTool(id: CheckId, name: string, args: Record<string, unknown>): Promise<ToolCallOutcome>;
  readResource(id: CheckId, uri: string, opts?: { probe?: boolean }): Promise<ReadOutcome>;
  getPrompt(id: CheckId, name: string, args: Record<string, string>): Promise<ReadOutcome>;
}

function safeTarget(target: ScanTarget): ScanTarget {
  return redactValue({ kind: target.kind, ...(target.command ? { command: redactCommand(target.command) } : {}),
    ...(target.url ? { url: target.url } : {}) });
}

export function failureReport(target: ScanTarget, error: string, active = true, startedAt = new Date().toISOString()): ScanReport {
  return redactValue({
    schemaVersion: "2.0", status: "failed", mode: active ? "active" : "inventory", errors: [error],
    target: safeTarget(target), startedAt, durationMs: Date.now() - Date.parse(startedAt),
    coverage: { excludedTools: [], untestedTools: [], limitations: ["Inventory unavailable; no assessment completed"], toolCalls: {}, resourceReads: 0 },
    inventorySizes: { tools: 0, resources: 0, prompts: 0 }, results: [], findings: [], score: null, mcpveilVersion: VERSION,
  });
}

export async function runScan(
  session: ForgeSession, target: ScanTarget, rawConfig: ForgeConfig,
  opts: { active?: boolean; signal?: AbortSignal } = {},
): Promise<ScanReport> {
  const config = validateConfig(rawConfig);
  const active = opts.active ?? true;
  const startedAt = new Date().toISOString();
  const signal = AbortSignal.any([AbortSignal.timeout(config.scanTimeoutMs), ...(opts.signal ? [opts.signal] : [])]);
  log.info(active ? "mode: active testing" : "mode: inventory-only (zero tool/resource invocations)");
  let inv: Inventory;
  try { inv = await inventory(session.client, { timeoutMs: config.timeoutMs, signal }); }
  catch (err) { return failureReport(target, `inventory failed: ${err instanceof Error ? err.message : String(err)}`, active, startedAt); }
  const excludedTools = inv.tools.filter((tool) => isExcluded(tool.name, config.allowTools)).map((tool) => tool.name);
  log.info(`inventory: ${inv.tools.length} tools (${excludedTools.length} excluded from active calls), ${inv.resources.length} resources, ${inv.prompts.length} prompts`);
  const findings: Finding[] = [];
  const results = new Map<CheckId, CheckResult>();
  const toolCalls: Record<string, number> = Object.fromEntries(inv.tools.map((tool) => [tool.name, 0]));
  const latencies: number[] = [];
  let resourceReads = 0;
  let contentRequests = 0;
  const resourceCache = new Map<string, Promise<ReadOutcome>>();
  const limit = (id: CheckId, message: string) => {
    const result = results.get(id);
    if (result && !result.limitations!.includes(message)) result.limitations!.push(message);
  };
  const track = <T extends ReadOutcome | ToolCallOutcome>(id: CheckId, label: string, outcome: T): T => {
    if (outcome.error) results.get(id)?.errors.push(`${label}: ${outcome.error}`);
    if (outcome.truncated) limit(id, `${label}: response exceeded capture limit; remaining content untested`);
    return outcome;
  };
  const ctx: ScanContext = {
    session, inv, config, target, active, results, limit, emit: (finding) => findings.push(finding),
    async invokeTool(id, name, args) {
      const skipped = !active ? "inventory-only" : isExcluded(name, config.allowTools) ? "excluded via policy" : undefined;
      if (skipped) return { ok: false, isError: false, text: "", durationMs: 0, skipped };
      if (signal.aborted) {
        limit(id, "overall scan deadline or cancellation reached");
        return { ok: false, isError: false, text: "", durationMs: 0, skipped: "scan cancelled" };
      }
      if ((toolCalls[name] ?? 0) >= config.maxCallsPerTool) {
        limit(id, `${name}: shared per-tool call budget exhausted`);
        return { ok: false, isError: false, text: "", durationMs: 0, skipped: "budget exhausted" };
      }
      toolCalls[name] = (toolCalls[name] ?? 0) + 1;
      results.get(id)!.invocations++;
      const outcome = await callToolSafe(session.client, name, args, config.timeoutMs, signal);
      latencies.push(outcome.durationMs);
      return track(id, name, outcome);
    },
    async readResource(id, uri, opts) {
      if (!active) return { ok: false, text: "", skipped: "inventory-only" };
      if (signal.aborted || contentRequests >= 1000) {
        limit(id, "resource/prompt request limit or scan deadline reached");
        return { ok: false, text: "", skipped: "request limit" };
      }
      if (!resourceCache.has(uri)) {
        contentRequests++; resourceReads++; results.get(id)!.resourceReads!++;
        resourceCache.set(uri, readResourceSafe(session.client, uri, config.timeoutMs, signal));
      }
      const outcome = await resourceCache.get(uri)!;
      if (opts?.probe && outcome.rejected) return { ok: true, text: "" };
      return track(id, uri, outcome);
    },
    async getPrompt(id, name, args) {
      if (!active) return { ok: false, text: "", skipped: "inventory-only" };
      if (signal.aborted || contentRequests >= 1000) {
        limit(id, "resource/prompt request limit or scan deadline reached");
        return { ok: false, text: "", skipped: "request limit" };
      }
      contentRequests++;
      return track(id, `prompt ${name}`, await getPromptSafe(session.client, name, args, config.timeoutMs, signal));
    },
  };
  for (const check of CHECKS) {
    const result: CheckResult = { meta: check.meta, findings: [], invocations: 0, errors: [], limitations: [], resourceReads: 0 };
    results.set(check.meta.id, result);
    if (config.checks[check.meta.id] === false) { result.skipped = "disabled via config"; continue; }
    log.info(`running check: ${check.meta.id}`);
    const before = findings.length;
    try { await check.run(ctx); }
    catch (err) { result.errors.push(`check failed: ${err instanceof Error ? err.message : String(err)}`); }
    result.findings = findings.slice(before);
  }
  const enabledActive = CHECKS.some((check) => check.meta.id !== "prompt-injection" && config.checks[check.meta.id] !== false);
  const untestedTools = active && enabledActive ? inv.tools.filter((tool) => !excludedTools.includes(tool.name) && !toolCalls[tool.name]).map((tool) => tool.name) : [];
  const limitations = [...new Set([
    ...[...results.values()].flatMap((result) => result.limitations ?? []),
    ...inv.tools.filter((tool) => !excludedTools.includes(tool.name)).flatMap((tool) => (tool.schemaLimitations ?? []).map((reason) => `${tool.name}: ${reason}`)),
    ...untestedTools.map((name) => `${name}: no supported active probe could be generated within the configured policy`),
  ])];
  const errors = [...(inv.errors ?? []), ...[...results.values()].flatMap((result) => result.errors.map((error) => `${result.meta.id}: ${error}`))];
  if (signal.aborted) errors.push("overall scan deadline or cancellation reached");
  const status = errors.length || limitations.length ? "partial" : "complete";
  const deduped = dedupe(findings);
  latencies.sort((a, b) => a - b);
  const latencyMs = { samples: latencies.length, p50: latencies[Math.max(0, Math.ceil(latencies.length * 0.50) - 1)] ?? 0, p95: latencies[Math.max(0, Math.ceil(latencies.length * 0.95) - 1)] ?? 0 };
  return redactValue({
    schemaVersion: "2.0", status, mode: active ? "active" : "inventory", errors,
    target: safeTarget(target), serverInfo: inv.serverInfo, startedAt, durationMs: Date.now() - Date.parse(startedAt),
    inventorySizes: { tools: inv.tools.length, resources: inv.resources.length, prompts: inv.prompts.length },
    coverage: { excludedTools, untestedTools, limitations, toolCalls, resourceReads, latencyMs },
    results: [...results.values()], findings: deduped,
    score: status === "complete" && active ? computeScore(deduped) : null, mcpveilVersion: VERSION,
  });
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    if (seen.has(finding.fingerprint)) return false;
    seen.add(finding.fingerprint); return true;
  }).sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
}

export function isExcluded(name: string, patterns: string[]): boolean {
  return patterns.some((pattern) => pattern.endsWith("*") ? name.startsWith(pattern.slice(0, -1)) : name === pattern);
}
const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
