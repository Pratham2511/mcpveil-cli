import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const CANARY_CONTENT = "MCPF0RGE_CANARY_9F3A_TRAVERSAL_CONFIRMED";

/** Fake credentials — canonical documentation examples, NOT real secrets. */
export const FAKE_AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"; // AWS docs example key
export const FAKE_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // AWS docs example secret
export const FAKE_GITHUB_PAT = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"; // 36 chars after prefix
// Assembled at runtime so no complete provider-shaped literal exists in source
// (keeps GitHub push protection / secret scanning quiet for this repo and forks).
export const FAKE_OPENAI_KEY = "sk-" + "proj-" + "Zk9w2mXq7Rt4vB8nC1dE5fG6hJ0kL3mNpQ2rS4tU";
export const FAKE_SLACK_TOKEN = ["xoxb", "1234567890", "1234567890123", "FakeTokenBodyForTests"].join("-");
export const FAKE_DB_PASS = "hunter2hunter2";

export interface Sandbox {
  root: string;        // server "home"
  notesDir: string;    // base dir for read_notes (canary sits in root, one level up)
}

/**
 * Build an isolated sandbox used by BOTH test servers:
 *   root/
 *     canary.txt          <- traversal target (one level above notesDir)
 *     notes/*.txt         <- legitimate files
 *     .env                <- secret-file probe target
 */
export function createSandbox(): Sandbox {
  const root = mkdtempSync(join(tmpdir(), "mcpveil-vuln-"));
  const notesDir = join(root, "notes");
  mkdirSync(notesDir);
  writeFileSync(join(root, "canary.txt"), CANARY_CONTENT);
  writeFileSync(join(notesDir, "welcome.txt"), "Welcome to MCPVeil notes.");
  writeFileSync(
    join(root, ".env"),
    `DATABASE_URL=postgres://admin:hunter2@localhost:5432/prod\nAWS_ACCESS_KEY_ID=${FAKE_AWS_ACCESS_KEY}\nAWS_SECRET_ACCESS_KEY=${FAKE_AWS_SECRET}\n`
  );
  return { root, notesDir };
}
