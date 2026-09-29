import { readFileSync, existsSync } from "node:fs";
import { z } from "zod";
import type { ForgeConfig } from "../types.js";

const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info", "never"]);

const ConfigSchema = z.object({
  checks: z.record(z.string(), z.boolean()).default({}),
  failOn: SeveritySchema.default("high"),
  timeoutMs: z.number().int().min(1000).max(120000).default(10000),
  maxCallsPerTool: z.number().int().min(1).max(200).default(12),
  allowTools: z.array(z.string()).default([]),
  ssrfCollaboratorUrl: z.string().url().optional(),
  output: z
    .object({
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
