import { it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
it("the Action refuses to launch a target without explicit authorization", () => {
  const root = mkdtempSync(join(tmpdir(), "mcpveil-consent-"));
  try {
    const result = spawnSync(process.execPath, [join(process.cwd(), "scripts/action.mjs")], { encoding: "utf8", env: { ...process.env,
      MCPVEIL_ACTION_AUTHORIZED: "false", RUNNER_TEMP: root, GITHUB_OUTPUT: join(root,"output"), MCPVEIL_ACTION_STDIO: "node synthetic-target.js" } });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("authoriz");
    expect(existsSync(join(root,"output"))).toBe(false);
  } finally { rmSync(root,{recursive:true,force:true}); }
});
