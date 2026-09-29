#!/usr/bin/env node
import { Command } from "commander";
import { writeFileSync } from "node:fs";
import { loadConfig, defaultConfig } from "./config/loader.js";
import { connect } from "./transports/factory.js";
import { runScan } from "./engine/scanner.js";
import { renderTerminal } from "./report/terminal.js";
import { renderJson } from "./report/json.js";
import { renderSarif } from "./report/sarif.js";
import type { ScanTarget, TransportKind, Severity, ForgeConfig } from "./types.js";
import { log } from "./utils/logger.js";

export const EXIT = { CLEAN: 0, POLICY_FAIL: 1, SCAN_FAIL: 2, USAGE: 3 } as const;

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

/** Errors that are the caller's fault → exit 3, never 2. */
class UsageError extends Error {}

interface CliOpts {
  stdio?: string;
  url?: string;
  transport?: TransportKind;
  config?: string;
  format?: "terminal" | "json" | "sarif";
  output?: string;
  failOn?: Severity | "never";
  timeout?: string;
  allowTool?: string[];
  skipCheck?: string[];
  inventoryOnly?: boolean;
  yes?: boolean;
}

const program = new Command();

program
  .name("mcpveil")
  .description("Deterministic security test suite for MCP servers: active payload-based scanning over real MCP sessions.")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan an MCP server (stdio command or URL)")
  .option("--stdio <command>", "spawn target via stdio, e.g. --stdio \"node dist/server.js\"")
  .option("--url <url>", "HTTP target (streamable HTTP with automatic SSE fallback)")
  .option("--transport <kind>", "force transport: stdio | streamable-http | sse")
  .option("-c, --config <path>", "path to mcpveil.config.json")
  .option("--format <fmt>", "terminal | json | sarif")
  .option("-o, --output <path>", "write report to file instead of stdout")
  .option("--fail-on <sev>", "exit 1 when findings at/above this severity", "high")
  .option("--timeout <ms>", "per-call timeout in ms")
  .option("--allow-tool <name...>", "exclude tools from active testing")
  .option("--skip-check <id...>", "disable specific checks")
  .option("--inventory-only", "connect + inventory + static pass only; zero tool invocations")
  .option("--yes", "consent: I understand the target will execute tool calls (stdio targets run server code)")
  .action(async (opts: CliOpts) => {
    try {
      process.exit(await scanAction(opts));
    } catch (err) {
      if (err instanceof UsageError) {
        log.error(err.message);
        process.exit(EXIT.USAGE);
      }
      log.error(err instanceof Error ? err.message : String(err));
      process.exit(EXIT.SCAN_FAIL);
    }
  });

async function scanAction(opts: CliOpts): Promise<number> {
  if (!opts.stdio && !opts.url) {
    throw new UsageError("provide --stdio <command> or --url <url>");
  }

  const config: ForgeConfig = { ...defaultConfig(), ...loadConfig(opts.config) };
  if (opts.format) config.output.format = opts.format;
  if (opts.output) config.output.path = opts.output;
  if (opts.failOn) config.failOn = opts.failOn;
  if (opts.timeout) {
    const ms = parseInt(opts.timeout, 10);
    if (Number.isNaN(ms) || ms < 1000) throw new UsageError(`--timeout must be an integer >= 1000 (got "${opts.timeout}")`);
    config.timeoutMs = ms;
  }
  if (opts.allowTool) config.allowTools.push(...opts.allowTool);
  if (opts.skipCheck) {
    for (const id of opts.skipCheck) config.checks[id as keyof typeof config.checks] = false;
  }

  const target: ScanTarget = opts.stdio
    ? { kind: opts.transport === "sse" ? "sse" : "stdio", command: shellSplit(opts.stdio) }
    : { kind: opts.transport === "sse" ? "sse" : "streamable-http", url: opts.url };

  if (!opts.yes && process.env.CI !== "true") {
    log.warn(
      "Active scanning will execute the target server and invoke its tools with attack payloads.\n" +
      "Only scan servers you own or have written permission to test. Run untrusted targets\n" +
      "inside a sandbox (Docker/VM). Re-run with --yes to proceed."
    );
    return EXIT.USAGE;
  }

  let session;
  try {
    session = await connect(target);
  } catch (err) {
    log.error(`could not connect to target: ${err instanceof Error ? err.message : err}`);
    return EXIT.SCAN_FAIL;
  }

  try {
    const report = await runScan(session, target, config, { active: !opts.inventoryOnly });
    const rendered =
      config.output.format === "json" ? renderJson(report)
      : config.output.format === "sarif" ? renderSarif(report)
      : renderTerminal(report);

    if (config.output.path) {
      writeFileSync(config.output.path, rendered, "utf8");
      log.info(`report written to ${config.output.path}`);
      if (config.output.format === "terminal") console.log(rendered);
    } else {
      console.log(rendered);
    }

    return shouldFail(report.findings.map((f) => f.severity), config.failOn) ? EXIT.POLICY_FAIL : EXIT.CLEAN;
  } finally {
    await session.close().catch(() => {});
  }
}

function shouldFail(severities: Severity[], failOn: Severity | "never"): boolean {
  if (failOn === "never") return false;
  const threshold = SEVERITIES.indexOf(failOn);
  if (threshold < 0) throw new UsageError(`--fail-on must be one of ${SEVERITIES.join("|")} | never`);
  return severities.some((s) => SEVERITIES.indexOf(s) <= threshold);
}

/** Minimal shell-like split honoring double quotes: "node a.js --x 1" → ["node","a.js","--x","1"] */
function shellSplit(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuote = false;
  for (const ch of s) {
    if (ch === '"') { inQuote = !inQuote; continue; }
    if (ch === " " && !inQuote) { if (cur) out.push(cur); cur = ""; continue; }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

program.parseAsync(process.argv);
