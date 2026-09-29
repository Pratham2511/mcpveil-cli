import pc from "picocolors";

const QUIET = process.env.MCPF0RGE_QUIET === "1";

export const log = {
  info: (msg: string) => { if (!QUIET) console.error(pc.dim(`[mcpveil] ${msg}`)); },
  warn: (msg: string) => { if (!QUIET) console.error(pc.yellow(`[mcpveil] ${msg}`)); },
  error: (msg: string) => console.error(pc.red(`[mcpveil] ${msg}`)),
};
