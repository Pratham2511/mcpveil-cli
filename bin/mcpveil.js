#!/usr/bin/env node
import("../dist/cli.js").catch((err) => {
  console.error("[mcpveil] failed to load dist/cli.js — did you run `npm run build`?", err?.message ?? err);
  process.exit(2);
});
