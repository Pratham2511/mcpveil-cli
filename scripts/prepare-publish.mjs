import { readFileSync, writeFileSync } from "node:fs";
import { publishingMetadata } from "./publish-metadata.mjs";

// Add provenance metadata from the GitHub Actions context at release time;
// tracked source files do not need any maintainer account identifiers.
const path = new URL("../package.json", import.meta.url);
const manifest = JSON.parse(readFileSync(path, "utf8"));
Object.assign(manifest, publishingMetadata(process.env.GITHUB_REPOSITORY));
writeFileSync(path, JSON.stringify(manifest, null, 2) + "\n");
console.log("Repository metadata prepared from the GitHub Actions context.");
