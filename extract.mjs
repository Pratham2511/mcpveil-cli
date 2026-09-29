// One-shot extractor: slices fenced code blocks out of the implementation
// prompt and writes them into the real file tree.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

const MD = "/home/z/my-project/MCPVeil-MVP-Implementation-Prompt.md";
const ROOT = "/home/z/my-project/mcpveil";
const lines = readFileSync(MD, "utf8").split("\n");

// [sectionHeaderLine, blockIndexWithinSection, targetPath]
const MAP = [
  [206, 0, "package.json"],
  [247, 0, "tsconfig.json"],
  [274, 0, "bin/mcpveil.js"],
  [283, 0, "src/types.ts"],
  [392, 0, "src/config/loader.ts"],
  [429, 0, "src/payloads/traversal.ts"],
  [482, 0, "src/payloads/injection.ts"],
  [537, 0, "src/payloads/ssrf.ts"],
  [592, 0, "src/payloads/secretPatterns.ts"],
  [640, 0, "src/transports/factory.ts"],
  [695, 0, "src/engine/inventory.ts"],
  [760, 0, "src/engine/executor.ts"],
  [856, 0, "src/engine/argPlanner.ts"],
  [952, 0, "src/utils/mask.ts"],
  [970, 0, "src/utils/logger.ts"],
  [986, 0, "src/engine/analyzer.ts"],
  [1053, 0, "src/checks/registry.ts"],
  [1131, 0, "src/engine/scanner.ts"],
  [1239, 0, "src/checks/pathTraversal.ts"],
  [1321, 0, "src/checks/injection.ts"],
  [1447, 0, "src/checks/ssrf.ts"],
  [1491, 0, "src/checks/credentialLeak.ts"],
  [1565, 0, "src/checks/promptInjection.ts"],
  [1630, 0, "src/report/score.ts"],
  [1651, 0, "src/report/terminal.ts"],
  [1707, 0, "src/report/json.ts"],
  [1707, 1, "src/report/sarif.ts"],
  [1795, 0, "src/cli.ts"],
  [1942, 0, "src/index.ts"],
  [1959, 0, "test/sandbox/seed.ts"],
  [1996, 0, "test/vulnerable-server/index.ts"],
  [2153, 0, "test/safe-server/index.ts"],
  [2236, 0, "test/e2e/accuracy-harness.test.ts"],
  [2285, 0, "test/unit/argPlanner.test.ts"],
  [2285, 1, "test/unit/analyzer.test.ts"],
  [2285, 2, "test/unit/secretPatterns.test.ts"],
  [2285, 3, "test/unit/sarif.test.ts"],
  [2285, 4, "test/unit/score.test.ts"],
  [2395, 0, "vitest.config.ts"],
  [2414, 0, ".github/workflows/ci.yml"],
  [2440, 0, ".github/workflows/security.yml"],
];

// Collect every fenced block with (openLine, closeLine, language)
const blocks = []; // { open, close, lang, section }
let section = null;
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  if (line.startsWith("### ")) section = { line: i + 1, text: line };
  const fenceOpen = /^```[A-Za-z]/.test(line);
  if (fenceOpen) {
    // find closing fence
    let close = -1;
    for (let j = i + 1; j < lines.length; j++) {
      if (lines[j].trim() === "```") { close = j + 1; break; }
    }
    if (close > 0) {
      blocks.push({ open: i + 1, close, lang: line.slice(3).trim(), section });
      i = close - 1; // skip past the block body
    }
  }
}

let ok = 0;
for (const [secLine, idx, target] of MAP) {
  const inSection = blocks.filter((b) => b.section && b.section.line === secLine);
  const block = inSection[idx];
  if (!block) { console.error(`MISSING block sec@${secLine}#${idx} for ${target}`); continue; }
  const content = lines.slice(block.open, block.close - 1).join("\n") + "\n";
  const out = join(ROOT, target);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, content, { mode: target === "bin/mcpveil.js" ? 0o755 : 0o644 });
  console.log(`wrote ${target} (${content.split("\n").length} lines, lang=${block.lang})`);
  ok++;
}
console.log(`\n${ok}/${MAP.length} files extracted`);
