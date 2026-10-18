import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { assertPatchedDependencies } from "./dependency-policy.mjs";

const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const lock = JSON.parse(readFileSync(new URL("../npm-shrinkwrap.json", import.meta.url), "utf8"));
assert.equal(process.env.RELEASE_TAG, `v${manifest.version}`, "Release tag must match package version");
assert.equal(lock.version, manifest.version, "Shrinkwrap version must match package version");
assert.equal(lock.packages[""].version, manifest.version);
assert.equal(manifest.repository.url, "git+https://github.com/Pratham2511/mcpveli.git");
assertPatchedDependencies(lock.packages);
console.log(`Release ${process.env.RELEASE_TAG} metadata and dependency versions verified.`);
