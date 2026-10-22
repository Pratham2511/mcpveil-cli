import { stageRelease } from "./release-artifact.mjs";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { assertPatchedDependencies } from "./dependency-policy.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
assert.equal(manifest.author, "MCPVeil contributors", "Package author must not contain personal contact details");
const scratch = mkdtempSync(join(tmpdir(), "mcpveil-package-"));
const runtime = process.env.MCPVEIL_TEST_NODE || process.execPath;
assert(process.env.npm_execpath, "Run this check using npm run test:package");

function run(command, args, cwd = scratch, env = process.env) {
  const result = spawnSync(command, args, {
    cwd, env, encoding: "utf8", timeout: 180_000, maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${result.error?.message ?? result.status}\n${result.stdout}\n${result.stderr}`);
  }
  return result.stdout;
}

function npm(args, cwd) {
  // A parent `npm publish --dry-run` must still pack/install the local test
  // artifact. These nested commands never perform a registry publish.
  const env = Object.fromEntries(Object.entries(process.env).filter(
    ([key]) => key.toLowerCase() !== "npm_config_dry_run"
  ));
  return run(process.execPath, [process.env.npm_execpath, ...args], cwd, env);
}

try {
  const stage = join(scratch, "stage");
  stageRelease(root, stage);
  const [pack] = JSON.parse(npm(["pack", "--json", "--ignore-scripts", "--pack-destination", scratch], stage));
  const files = new Set(pack.files.map(({ path }) => path));
  for (const required of ["package.json", "npm-shrinkwrap.json", "bin/mcpveil.js", "dist/cli.js", "dist/index.js", "dist/version.js"]) {
    assert(files.has(required), `Published package is missing ${required}`);
  }
  for (const path of files) {
    assert(!/^(test|src|scripts|\.github|node_modules)\//.test(path), `Unexpected published file: ${path}`);
    assert(!/(^|\/)\.env(?:\.|$)/.test(path), `Unexpected environment file: ${path}`);
    assert(!/(^|\/)(?:\.npmrc|\.aws|\.ssh|\.codex|\.agents|id_rsa|id_ed25519|credentials\.json)(?:\/|$|\.)/.test(path),
      `Unexpected private configuration file: ${path}`);
    assert(!/\.(?:pem|key|p12|pfx)$/.test(path), `Unexpected key file: ${path}`);
  }

  writeFileSync(join(scratch, "package.json"), JSON.stringify({ name: "mcpveil-package-smoke", private: true, version: "0.0.0" }));
  npm(["install", join(scratch, pack.filename), "--engine-strict", "--ignore-scripts", "--no-audit", "--no-fund"]);
  npm(["ls", "--omit=dev", "--all", "--json"]); // fails on any extraneous/development tree
  const installed = join(scratch, "node_modules", manifest.name);
  const installedManifest = JSON.parse(readFileSync(join(installed, "package.json"), "utf8"));
  assert.equal(installedManifest.devDependencies, undefined);
  assert.equal(installedManifest.scripts, undefined);
  const installedLock = JSON.parse(readFileSync(join(installed, "npm-shrinkwrap.json"), "utf8"));
  assert(Object.values(installedLock.packages).every((entry) => !entry.dev), "Development packages leaked into the installed lock");
  for (const path of Object.keys(installedLock.packages)) assert(!/node_modules\/(?:@modelcontextprotocol\/sdk|qs|hono|ip-address|vitest|typescript|tsx)$/.test(path), `Unexpected development dependency: ${path}`);
  const lock = JSON.parse(readFileSync(join(scratch, "package-lock.json"), "utf8"));
  assertPatchedDependencies(lock.packages);
  assert.equal(run(runtime, [join(installed, "bin/mcpveil.js"), "--version"]).trim(), manifest.version);
  assert.match(run(runtime, [join(installed, "bin/mcpveil.js"), "--help"]), /scan/);
  run(runtime, ["--input-type=module", "-e", `
    import assert from 'node:assert/strict';
    import { runScan, connect, defaultConfig } from '${manifest.name}';
    import { FORGE_CLIENT_VERSION } from './node_modules/${manifest.name}/dist/transports/factory.js';
    assert.equal(typeof runScan, 'function');
    assert.equal(typeof connect, 'function');
    assert.equal(defaultConfig().failOn, 'high');
    assert.equal(FORGE_CLIENT_VERSION, '${manifest.version}');
  `]);
  // Exercise the shipped Action launcher against this exact installed tarball.
  const runner = join(scratch, "runner");
  const actionPrefix = join(runner, "mcpveil-action");
  mkdirSync(actionPrefix, { recursive: true });
  symlinkSync(join(scratch, "node_modules"), join(actionPrefix, "node_modules"), "junction");
  const actionOutput = join(runner, "outputs.txt");
  run(runtime, [join(root, "scripts/action.mjs")], root, { ...process.env,
    RUNNER_TEMP: runner, GITHUB_OUTPUT: actionOutput, MCPVEIL_ACTION_AUTHORIZED: "true",
    MCPVEIL_ACTION_STDIO: `${JSON.stringify(runtime)} ${JSON.stringify(join(root, "test/fixtures/security-cases.mjs"))} echo`,
    MCPVEIL_ACTION_HEADERS: "{}", MCPVEIL_ACTION_PROTOCOL: "legacy" });
  const actionFiles = Object.fromEntries(readFileSync(actionOutput, "utf8").trim().split("\n").map((line) => line.split("=")));
  assert.equal(JSON.parse(readFileSync(actionFiles.json, "utf8")).status, "complete");
  assert.equal(JSON.parse(readFileSync(actionFiles.sarif, "utf8")).version, "2.1.0");
  console.log(`Packed ${manifest.name}@${manifest.version}: CLI, API, and patched installed dependencies verified on ${run(runtime, ["--version"]).trim()}.`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
