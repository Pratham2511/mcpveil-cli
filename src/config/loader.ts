import { readFileSync, existsSync } from "node:fs";
import { z } from "zod";
import type { ForgeConfig } from "../types.js";

const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info", "never"]);

export const CHECK_IDS = ["path-traversal", "command-injection", "sql-injection", "ssrf", "credential-leak", "prompt-injection"] as const;

const ConfigSchema = z.strictObject({
  checks: z.partialRecord(z.enum(CHECK_IDS), z.boolean()).default({}),
  failOn: SeveritySchema.default("high"),
  timeoutMs: z.number().int().min(1000).max(120000).default(10000),
  scanTimeoutMs: z.number().int().min(1000).max(3600000).default(120000),
  maxCallsPerTool: z.number().int().min(1).max(200).default(128),
  allowTools: z.array(z.string()).default([]),
  ssrfCollaboratorUrl: z.string().url().optional(),
  output: z
    .strictObject({
      format: z.enum(["terminal", "json", "sarif"]).default("terminal"),
      path: z.string().optional(),
    })
    .default({ format: "terminal" }),
});

export function defaultConfig(): ForgeConfig {
  return ConfigSchema.parse({});
}

export function loadConfig(path?: string): ForgeConfig {
  const base = defaultConfig();
  if (!path) return base;
  if (!existsSync(path)) throw new Error(`config not found: ${path}`);
  const raw = JSON.parse(readFileSync(path, "utf8"));
  return ConfigSchema.parse({ ...base, ...raw });
}

export function validateConfig(value: unknown): ForgeConfig {
  return ConfigSchema.parse(value);
}
