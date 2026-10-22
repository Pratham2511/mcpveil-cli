# Publishing MCPVeil to npm

The next release is `mcpveil-cli@0.2.0`. Merging its PR runs CI; publishing a
GitHub release with tag `v0.2.0` starts `.github/workflows/publish.yml`.
The workflow requires the tagged commit to be on `main` and its version to
match `package.json`. It runs dependency checks, lint, tests, and a fresh
package-install check before publishing to npmjs.com.

## One-time npm account setup

After merging, open the [package settings](https://www.npmjs.com/package/mcpveil-cli/access)
and add a GitHub Actions trusted publisher:

| Field | Value |
| --- | --- |
| Organization or user | The account or organization that owns this GitHub repository |
| Repository | `mcpveli` (name only, **not** the GitHub URL) |
| Workflow filename | `publish.yml` |
| Environment | Leave empty |
| Allowed action | Allow `npm publish` |

This uses OIDC and provenance; no npm token or GitHub secret is needed.
Create the publisher close to release time: npm requires its first publish
within two days. See [npm's trusted publishing guide](https://docs.npmjs.com/trusted-publishers/).

**Pending validation** is expected until the first successful workflow publish.
If the publisher display contains a second `https://github.com/` after the
owner, correct the Repository field to its name only before publishing.

## Release steps

1. Review and merge the security/release PR after all checks pass.
2. Complete the trusted-publisher setup above.
3. Create a GitHub release from `main` with tag `v0.2.0`, then publish it.
4. Check the **Publish to npm** workflow and the package's npm page.

From an authenticated GitHub CLI checkout of this repository, the release
command is:

```bash
gh release create v0.2.0 --target main --title v0.2.0 --generate-notes
```

This triggers `npm publish` inside GitHub Actions, where OIDC is available.
A local `npm publish` does not validate a GitHub Actions trusted publisher.

Repository URLs required by npm provenance are generated from GitHub's
`GITHUB_REPOSITORY` context by `scripts/prepare-publish.mjs`. The tracked
manifest uses a community author and does not contain personal contact
details. Provenance and npm publisher attribution still identify the source
repository and registry account; they are public publishing records.

For later releases, update `package.json` and run `npm install --package-lock-only`
to synchronize `npm-shrinkwrap.json`. The CLI and MCP client read the package
version automatically. Use a matching `v<version>` release tag.

## Dependency security

`npm-shrinkwrap.json` replaces `package-lock.json` and ships with this CLI so
installations retain the verified transitive dependencies:

| Dependency | Previous | Updated |
| --- | --- | --- |
| `qs` | 6.16.0 | 6.16.1 |
| `ip-address` | 10.7.2 | 10.7.4 |
| `hono` | 4.13.9 | 4.13.13 |

Keep updating this lockfile for future advisories. `npm run test:package`
checks a fresh tarball installation for the patched minimum versions.

Advisories: [qs](https://github.com/ljharb/qs/security/advisories/GHSA-6pq8-jhm2-2vcw),
[ip-address](https://github.com/beaugunderson/ip-address/security/advisories/GHSA-rxp7-6hxx-x8q5),
and [Hono](https://github.com/honojs/hono/security/advisories/GHSA-5r4p-p66f-jhc7).

Release validation builds and tests the tarball in a job without OIDC publishing
permission. A separate publisher downloads that immutable workflow artifact,
verifies its SHA-256 and publishes with lifecycle scripts disabled. Keep the
trusted publisher workflow filename `publish.yml`.
