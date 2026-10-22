import { it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const runtime = process.env.MCPVEIL_TEST_NODE || process.execPath;
const cli = join(process.cwd(), "dist/cli.js");
function run(args: string[]) { const r = spawnSync(runtime, [cli, ...args], { encoding: "utf8", timeout: 20000 }); if (r.error) throw r.error; return r; }
it("applies a reviewed baseline through the real CLI, rejects scope/expiry and preserves partial failure", () => {
  const root = mkdtempSync(join(tmpdir(), "mcpveil-policy-"));
  const report = join(root, "report.json"), baseline = join(root, "baseline.json"), events = join(root, "events.jsonl");
  const command = `${JSON.stringify(runtime)} test/fixtures/security-cases.mjs secret ${JSON.stringify(events)}`;
  const scan = ["scan", "--stdio", command, "--yes", "--format", "json", "-o", report];
  try {
    expect(run(scan).status).toBe(1);
    expect(run(["baseline", "create", "--report", report, "--target-id", "ci-read-only", "--reason", "Reviewed fixture", "--expires", new Date(Date.now()+86400000).toISOString(), "-o", baseline]).status).toBe(0);
    const accepted = run([...scan,"--baseline",baseline,"--target-id","ci-read-only"]);
    expect(accepted.status, accepted.stderr).toBe(0);
    expect(JSON.parse(readFileSync(report,"utf8")).findings.every((f: any)=> f.baselineState === "accepted")).toBe(true);
    const before = readFileSync(events,"utf8");
    expect(run([...scan,"--baseline",baseline,"--target-id","other-account"]).status).toBe(3);
    expect(readFileSync(events,"utf8")).toBe(before);
    const data = JSON.parse(readFileSync(baseline,"utf8"));
    writeFileSync(baseline,JSON.stringify({...data,expiresAt:"2000-01-01T00:00:00.000Z"}));
    expect(run([...scan,"--baseline",baseline,"--target-id","ci-read-only"]).status).toBe(3);
    expect(readFileSync(events,"utf8")).toBe(before);
  } finally { rmSync(root,{recursive:true,force:true}); }
});
it("compares actual tool metadata drift without writing descriptions to the snapshot", () => {
  const root = mkdtempSync(join(tmpdir(),"mcpveil-drift-"));
  try {
    const spec = join(root,"tools.json"), snapshot = join(root,"tools.snapshot.json");
    const tool = {name:"lookup",description:"Private original description",inputSchema:{type:"object",properties:{query:{type:"string"}},required:["query"]}};
    writeFileSync(spec,JSON.stringify({tools:[tool]}));
    const command = `${JSON.stringify(runtime)} test/fixtures/security-cases.mjs drift ${JSON.stringify(join(root,"events.jsonl"))} ${JSON.stringify(spec)}`;
    const scan = ["scan","--stdio",command,"--inventory-only","--yes","--target-id","ci","--format","json"];
    expect(run([...scan,"--write-snapshot",snapshot]).status).toBe(0);
    expect(existsSync(snapshot)).toBe(true);
    expect(readFileSync(snapshot,"utf8")).not.toMatch(/Private|lookup|query/);
    expect(run([...scan,"--snapshot",snapshot]).status).toBe(0);
    writeFileSync(spec,JSON.stringify({tools:[{...tool,description:"Changed description"}]}));
    const changed = run([...scan,"--snapshot",snapshot,"--fail-on","never"]);
    expect(changed.status,changed.stderr).toBe(1);
    expect(JSON.parse(changed.stdout).policy.drift.changed).toHaveLength(1);
  } finally { rmSync(root,{recursive:true,force:true}); }
});
