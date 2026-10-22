import pc from "picocolors";
import { redactText } from "./redact.js";

const QUIET = process.env.MCPF0RGE_QUIET === "1";

export const log = {
  info: (msg: string) => { if (!QUIET) console.error(pc.dim(`[mcpveil] ${redactText(msg)}`)); },
  warn: (msg: string) => { if (!QUIET) console.error(pc.yellow(`[mcpveil] ${redactText(msg)}`)); },
  error: (msg: string) => console.error(pc.red(`[mcpveil] ${redactText(msg)}`)),
};
