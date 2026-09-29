import type {
  ForgeConfig, Inventory, ScanReport, ScanTarget, CheckResult, Finding, CheckId,
} from "../types.js";
import type { ForgeSession } from "../transports/factory.js";
import { inventory } from "./inventory.js";
import { CHECKS } from "../checks/registry.js";
import { runPromptInjection } from "../checks/promptInjection.js";
import { computeScore } from "../report/score.js";
import { FORGE_CLIENT_VERSION } from "../transports/factory.js";
import { log } from "../utils/logger.js";

export interface ScanContext {
  session: ForgeSession;
  inv: Inventory;
  config: ForgeConfig;
  target: ScanTarget;
  /** false in --inventory-only mode: checks must not invoke tools */
  active: boolean;
  emit(f: Finding): void;
  /** shared mutable registry of results, keyed by check id */
  results: Map<CheckId, CheckResult>;
  registerError(id: CheckId, msg: string): void;
  countInvocation(id: CheckId): void;
}

export async function runScan(
  session: ForgeSession,
  target: ScanTarget,
  config: ForgeConfig,
  opts: { active?: boolean } = {}
): Promise<ScanReport> {
  const active = opts.active ?? true;
  const startedAt = new Date().toISOString();
  const t0 = Date.now();

  log.info(active ? "mode: active testing (tool invocations enabled)" : "mode: inventory-only (zero tool invocations)");

  log.info("collecting inventory…");
  const inv = await inventory(session.client);
  const fullToolCount = inv.tools.length;
  if (config.allowTools.length > 0) {
    const before = inv.tools.length;
    const excluded = inv.tools.filter((t) => isExcluded(t.name, config.allowTools));
    inv.tools = inv.tools.filter((t) => !isExcluded(t.name, config.allowTools));
    if (excluded.length > 0) {
      log.info(`active testing excluded ${excluded.length} tool(s) via allow-tool: ${excluded.map((t) => t.name).join(", ")}`);
    }
    if (inv.tools.length === 0 && before > 0) {
      log.warn("allow-tool excluded every tool; only static checks will run");
    }
  }
  log.info(`inventory: ${inv.tools.length} tools (${fullToolCount - inv.tools.length} excluded), ${inv.resources.length} resources, ${inv.prompts.length} prompts`);

  const findings: Finding[] = [];
  const results = new Map<CheckId, CheckResult>();
  const ctx: ScanContext = {
    session,
    inv,
    config,
    target,
    active,
    emit: (f) => findings.push(f),
    results,
    registerError: (id, msg) => {
      const r = results.get(id);
      if (r) r.errors.push(msg);
    },
    countInvocation: (id) => {
      const r = results.get(id);
      if (r) r.invocations += 1;
    },
  };

  for (const check of CHECKS) {
    if (config.checks[check.meta.id] === false) {
      results.set(check.meta.id, {
        meta: check.meta, findings: [], invocations: 0, errors: [],
        skipped: "disabled via config",
      });
      continue;
    }
    log.info(`running check: ${check.meta.id}`);
    const result: CheckResult = { meta: check.meta, findings: [], invocations: 0, errors: [] };
    results.set(check.meta.id, result);
    const before = findings.length;
    try {
      await check.run(ctx);
    } catch (err: any) {
      // a crashing check must never kill the scan
      result.errors.push(`check crashed: ${err?.message ?? String(err)}`);
      log.warn(`check ${check.meta.id} crashed: ${err?.message ?? err}`);
    }
    result.findings = findings.slice(before);
  }

  const deduped = dedupe(findings);
  return {
    target,
    serverInfo: inv.serverInfo,
    startedAt,
    durationMs: Date.now() - t0,
    inventorySizes: { tools: inv.tools.length, resources: inv.resources.length, prompts: inv.prompts.length },
    results: [...results.values()],
    findings: deduped,
    score: computeScore(deduped),
    mcpveilVersion: FORGE_CLIENT_VERSION,
  };
}

function dedupe(fs: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of fs) {
    if (!seen.has(f.fingerprint)) { seen.add(f.fingerprint); out.push(f); }
  }
  return out.sort(bySeverity);
}

/** allow-tool semantics: exact name, or `prefix*` wildcard (e.g. "create_*"). */
export function isExcluded(name: string, patterns: string[]): boolean {
  return patterns.some((p) => {
    if (p.endsWith("*")) return name.startsWith(p.slice(0, -1));
    return name === p;
  });
}

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
function bySeverity(a: Finding, b: Finding): number {
  return (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
}
