#!/usr/bin/env node
const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 22 || (major === 22 && minor < 12)) {
  console.error(`[mcpveil] Node >=22.12.0 is required; current runtime is ${process.version}. Install a supported Node LTS release.`);
  process.exit(3);
}
import("../dist/cli.js").catch((err) => {
  console.error("[mcpveil] failed to load dist/cli.js — did you run `npm run build`?", err?.message ?? err);
  process.exit(2);
});
