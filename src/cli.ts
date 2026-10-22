#!/usr/bin/env node
import { Command, Option, InvalidArgumentError, CommanderError } from "commander";
import { writeFileSync } from "node:fs";
import { loadConfig, validateConfig, CHECK_IDS } from "./config/loader.js";
import { connect } from "./transports/factory.js";
import { runScan, failureReport } from "./engine/scanner.js";
import { renderTerminal } from "./report/terminal.js";
import { renderJson } from "./report/json.js";
import { renderSarif } from "./report/sarif.js";
import type { ScanTarget, TransportKind, Severity, ForgeConfig, ScanReport } from "./types.js";
import { log } from "./utils/logger.js";
import { redactText } from "./utils/redact.js";
import { VERSION } from "./version.js";

export const EXIT = { CLEAN: 0, POLICY_FAIL: 1, SCAN_FAIL: 2, USAGE: 3 } as const;
const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
class UsageError extends Error {}
interface CliOpts {
  stdio?: string; url?: string; transport?: TransportKind; config?: string;
  format?: "terminal" | "json" | "sarif"; output?: string; failOn?: Severity | "never";
  timeout?: number; scanTimeout?: number; maxCallsPerTool?: number;
  allowTool?: string[]; skipCheck?: string[]; env?: string[]; inventoryOnly?: boolean; yes?: boolean;
}
function integer(min: number, max: number) {
  return (input: string) => {
    if (!/^\d+$/.test(input) || !Number.isSafeInteger(Number(input)) || Number(input) < min || Number(input) > max) {
      throw new InvalidArgumentError(`must be an integer between ${min} and ${max}`);
    }
    return Number(input);
  };
}
const program = new Command().name("mcpveil")
  .description("Local security regression tests for MCP servers.").version(VERSION).exitOverride()
  .configureOutput({ writeErr: (text) => process.stderr.write(redactText(text)), writeOut: (text) => process.stdout.write(redactText(text)) });

program.command("scan").description("Scan an explicitly authorized MCP server")
  .option("--stdio <command>", "launch an exact command through stdio (no shell)")
  .option("--url <url>", "HTTP target, with legacy SSE fallback")
  .addOption(new Option("--transport <kind>", "force a transport").choices(["stdio", "streamable-http", "sse"]))
  .option("-c, --config <path>", "JSON configuration")
  .addOption(new Option("--format <format>", "report format").choices(["terminal", "json", "sarif"]))
  .option("-o, --output <path>", "report destination")
  .addOption(new Option("--fail-on <severity>", "policy failure threshold").choices([...SEVERITIES, "never"]))
  .option("--timeout <ms>", "per-request timeout, including inventory", integer(1000, 120000))
  .option("--scan-timeout <ms>", "overall assessment deadline", integer(1000, 3600000))
  .option("--max-calls-per-tool <count>", "shared budget across all checks, including baselines", integer(1, 200))
  .option("--allow-tool <name...>", "exclude tools from active calls (static metadata is still inspected)")
  .option("--skip-check <id...>", "disable named checks")
  .option("--env <name>", "explicitly forward one environment variable (repeatable)", (value: string, previous: string[]) => [...previous, value], [])
  .option("--inventory-only", "metadata only: zero tools/call, resources/read, or prompts/get requests")
  .option("--yes", "authorize launching/contacting this target and the selected scan mode")
  .action(async (opts: CliOpts) => {
    try { process.exitCode = await scanAction(opts); }
    catch (err) { log.error(err instanceof Error ? err.message : String(err)); process.exitCode = err instanceof UsageError ? EXIT.USAGE : EXIT.SCAN_FAIL; }
  });

async function scanAction(opts: CliOpts): Promise<number> {
  if (Boolean(opts.stdio) === Boolean(opts.url)) throw new UsageError("provide exactly one of --stdio or --url");
  if ((opts.stdio && opts.transport && opts.transport !== "stdio") || (opts.url && opts.transport === "stdio")) {
    throw new UsageError("transport must match the selected stdio or URL target");
  }
  let config: ForgeConfig;
  try {
    config = loadConfig(opts.config);
    if (opts.format !== undefined) config.output.format = opts.format;
    if (opts.output !== undefined) config.output.path = opts.output;
    if (opts.failOn !== undefined) config.failOn = opts.failOn;
    if (opts.timeout !== undefined) config.timeoutMs = opts.timeout;
    if (opts.scanTimeout !== undefined) config.scanTimeoutMs = opts.scanTimeout;
    if (opts.maxCallsPerTool !== undefined) config.maxCallsPerTool = opts.maxCallsPerTool;
    config.allowTools.push(...(opts.allowTool ?? []));
    for (const id of opts.skipCheck ?? []) {
      if (!(CHECK_IDS as readonly string[]).includes(id)) throw new UsageError(`unknown check: ${id}`);
      config.checks[id as keyof typeof config.checks] = false;
    }
    config = validateConfig(config);
  } catch (err) { throw new UsageError(`invalid configuration: ${err instanceof Error ? err.message : String(err)}`); }
  const inheritEnv = opts.env ?? [];
  for (const key of inheritEnv) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || process.env[key] === undefined) throw new UsageError(`environment variable unavailable or invalid: ${key}`);
  }
  let target: ScanTarget;
  if (opts.stdio) {
    const command = shellSplit(opts.stdio);
    if (!command[0]) throw new UsageError("stdio command is empty");
    target = { kind: "stdio", command, inheritEnv };
  } else {
    let url: URL;
    try { url = new URL(opts.url!); } catch { throw new UsageError("target URL must be a valid HTTP(S) URL"); }
    if (!["https:", "http:"].includes(url.protocol) || url.username || url.password) throw new UsageError("use an HTTP(S) URL without embedded credentials");
    target = { kind: opts.transport === "sse" ? "sse" : "streamable-http", url: url.href };
  }
  if (!opts.yes) throw new UsageError("Use --yes to authorize this target. Stdio targets execute server code even in inventory-only mode; isolate untrusted servers.");
  let report: ScanReport;
  let session;
  const signal = AbortSignal.timeout(config.scanTimeoutMs);
  try { session = await connect(target, { timeoutMs: config.timeoutMs, signal }); }
  catch (err) {
    report = failureReport(target, `connection failed: ${err instanceof Error ? err.message : String(err)}`, !opts.inventoryOnly);
    output(report, config); return EXIT.SCAN_FAIL;
  }
  try {
    report = await runScan(session, target, config, { active: !opts.inventoryOnly, signal });
    output(report, config);
    if (report.status !== "complete") return EXIT.SCAN_FAIL;
    if (config.failOn === "never") return EXIT.CLEAN;
    const threshold = SEVERITIES.indexOf(config.failOn);
    return report.findings.some((finding) => SEVERITIES.indexOf(finding.severity) >= threshold) ? EXIT.POLICY_FAIL : EXIT.CLEAN;
  } finally { await session.close().catch(() => {}); }
}

function output(report: ScanReport, config: ForgeConfig): void {
  const rendered = config.output.format === "json" ? renderJson(report) : config.output.format === "sarif" ? renderSarif(report) : renderTerminal(report);
  if (config.output.path) {
    writeFileSync(config.output.path, rendered, "utf8"); log.info(`report written to ${config.output.path}`);
  } else console.log(rendered);
}

/** Quoted argv parsing only. No expansion or shell evaluation. */
function shellSplit(input: string): string[] {
  const out: string[] = [];
  let current = ""; let quote = ""; let started = false;
  for (let index = 0; index < input.length; index++) {
    const char = input[index]!;
    if (quote) {
      if (char === quote) { quote = ""; continue; }
      if (char === "\\" && quote === '"' && ['"', "\\"].includes(input[index + 1] ?? "")) { current += input[++index]; continue; }
      current += char;
    } else if (char === '"' || char === "'") { quote = char; started = true; }
    else if (/\s/.test(char)) { if (started) { out.push(current); current = ""; started = false; } }
    else if (char === "\\" && /[\s"'\\]/.test(input[index + 1] ?? "")) { current += input[++index]; started = true; }
    else { current += char; started = true; }
  }
  if (quote) throw new UsageError("unclosed quote in stdio command");
  if (started) out.push(current);
  return out;
}

if (process.argv.length <= 2) program.outputHelp();
else program.parseAsync(process.argv).catch((err: unknown) => {
  if (err instanceof CommanderError) process.exitCode = err.exitCode === 0 ? EXIT.CLEAN : EXIT.USAGE;
  else { log.error(err instanceof Error ? err.message : String(err)); process.exitCode = EXIT.USAGE; }
});
