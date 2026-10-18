import { readFileSync } from "node:fs";

// Both src/ and dist/ sit directly below the package manifest.
const manifest: { version: string } = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8")
);

export const VERSION = manifest.version;
