import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";

const root = process.cwd();
const runtime = process.env.MCPVEIL_TEST_NODE;
const legacyNpm = process.env.MCPVEIL_TEST_NPM;
assert(runtime && legacyNpm, "Set MCPVEIL_TEST_NODE and MCPVEIL_TEST_NPM to the unsupported runtime and bundled npm");
const scratch = mkdtempSync(join(tmpdir(), "mcpveil-runtime-policy-"));
try {
  const cli = spawnSync(runtime, [join(root, "bin/mcpveil.js"), "--version"], { encoding: "utf8" });
  assert.equal(cli.status, 3);
  assert.match(cli.stderr, /Node >=22\.12\.0 is required/);
  const npmCli = process.env.npm_execpath ?? join(dirname(process.execPath), "../lib/node_modules/npm/bin/npm-cli.js");
  const pack = spawnSync(process.execPath, [npmCli, "pack", "--ignore-scripts", "--json", "--pack-destination", scratch], { cwd: root, encoding: "utf8" });
  assert.equal(pack.status, 0, pack.stderr);
  const [{ filename }] = JSON.parse(pack.stdout);
  writeFileSync(join(scratch, "package.json"), JSON.stringify({ name: "runtime-policy-check", private: true, version: "0.0.0" }));
  const install = spawnSync(runtime, [realpathSync(legacyNpm), "install", join(scratch, filename), "--engine-strict", "--ignore-scripts", "--no-audit", "--no-fund"], {
    cwd: scratch, encoding: "utf8", env: { ...process.env, npm_config_engine_strict: "true" }, timeout: 60000,
  });
  assert.notEqual(install.status, 0);
  assert.match(install.stderr, /EBADENGINE/);
  assert.match(install.stderr, /mcpveil-cli/);
  console.log("Unsupported runtime fails early with a clear CLI diagnostic and engine-strict installation rejection.");
} finally { rmSync(scratch, { recursive: true, force: true }); }
