import { loadConfig } from "./config/loader.js";
import { VERSION } from "./version.js";
export function doctor(configPath?: string, requiredEnv: string[] = []) {
  const config = loadConfig(configPath);
  const missingEnv = requiredEnv.filter((key) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || process.env[key] === undefined);
  return { version: VERSION, node: process.versions.node, platform: process.platform, architecture: process.arch,
    status: missingEnv.length ? "needs-attention" : "ready", configuration: "valid", missingEnv,
    policy: { timeoutMs: config.timeoutMs, scanTimeoutMs: config.scanTimeoutMs, maxCallsPerTool: config.maxCallsPerTool, failOn: config.failOn },
    isolation: "Target isolation must be provided by the caller (container/VM); stdio alone is not a sandbox.",
    next: "mcpveil scan --stdio \"node path/to/server.js\" --yes" };
}
