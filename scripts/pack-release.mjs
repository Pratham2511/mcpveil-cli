import { mkdtempSync, rmSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { stageRelease } from './release-artifact.mjs';
const root = fileURLToPath(new URL('../', import.meta.url));
const destination = resolve(process.argv[2] || '.');
const stage = mkdtempSync(join(tmpdir(), 'mcpveil-release-stage-'));
try {
  stageRelease(root, stage);
  const npmCli = process.env.npm_execpath || join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js');
  const result = spawnSync(process.execPath, [npmCli, 'pack', '--ignore-scripts', '--pack-destination', destination], { cwd: stage, stdio: 'inherit' });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
} finally { rmSync(stage, { recursive: true, force: true }); }
