import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { appendFileSync, writeFileSync, readFileSync, mkdtempSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const env = process.env;
if (env.MCPVEIL_ACTION_AUTHORIZED !== 'true') throw new Error('Set authorized: true only after authorizing this target.');
const installed = join(env.RUNNER_TEMP, 'mcpveil-action', 'node_modules', 'mcpveil-cli');
const out = mkdtempSync(join(env.RUNNER_TEMP, 'mcpveil-report-'));
const json = join(out, 'report.json'), sarif = join(out, 'report.sarif');
const args = [join(installed, 'bin', 'mcpveil.js'), 'scan', '--yes', '--format', 'json', '--output', json];
for (const [key, flag] of [['STDIO','--stdio'],['URL','--url'],['CONFIG','--config'],['BEARER','--bearer-env'],['PROTOCOL','--protocol'],['AUTH_POLICY','--auth-policy'],['BASELINE','--baseline'],['SNAPSHOT','--snapshot'],['TARGET_ID','--target-id']])
 if (env[`MCPVEIL_ACTION_${key}`]) args.push(flag, env[`MCPVEIL_ACTION_${key}`]);
const forward = JSON.parse(env.MCPVEIL_ACTION_FORWARD_ENV || '[]');
if (!Array.isArray(forward) || forward.some((name) => typeof name !== 'string')) throw new Error('forward-env must be a JSON array of variable names');
for (const name of forward) args.push('--env', name);
const headers = JSON.parse(env.MCPVEIL_ACTION_HEADERS || '{}');
if (!headers || Array.isArray(headers) || typeof headers !== 'object') throw new Error('header-env must be a JSON object');
for (const [name, variable] of Object.entries(headers)) {
 if (typeof variable !== 'string') throw new Error('header-env values must be environment variable names');
 args.push('--header-env', `${name}=${variable}`);
}
if (env.MCPVEIL_ACTION_ORIGIN === 'true') args.push('--check-origin');
// Values are passed directly as argv; target input never enters a shell script.
const result = spawnSync(process.execPath, args, { stdio: ['ignore', 'inherit', 'inherit'] });
appendFileSync(env.GITHUB_OUTPUT, `json=${json}\nsarif=${sarif}\n`);
try {
 const report = JSON.parse(readFileSync(json, 'utf8'));
 const { renderSarif } = await import(pathToFileURL(join(installed,'dist','index.js')).href);
 writeFileSync(sarif, renderSarif(report), { mode: 0o600 });
} catch { console.error('No complete report artifact was available; inspect scan diagnostics.'); }
process.exitCode = result.error ? 2 : result.status ?? 2;
