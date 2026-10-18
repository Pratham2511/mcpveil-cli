import assert from "node:assert/strict";

// Patched floors for the three SDK transitive dependencies reported by Snyk.
const minimumVersions = { qs: "6.16.1", "ip-address": "10.7.4", hono: "4.13.13" };

export function assertPatchedDependencies(packages) {
  for (const [name, minimum] of Object.entries(minimumVersions)) {
    const matches = Object.entries(packages).filter(([path]) =>
      path.endsWith(`node_modules/${name}`)
    );
    assert(matches.length > 0, `Missing dependency in lockfile: ${name}`);
    for (const [path, { version }] of matches) {
      assert(/^\d+\.\d+\.\d+$/.test(version), `Unexpected ${path} version: ${version}`);
      const actual = version.split(".").map(Number);
      const floor = minimum.split(".").map(Number);
      const firstDifference = actual.findIndex((part, i) => part !== floor[i]);
      assert(
        firstDifference === -1 || actual[firstDifference] > floor[firstDifference],
        `${path}@${version} is below the patched minimum ${minimum}`
      );
    }
  }
}
