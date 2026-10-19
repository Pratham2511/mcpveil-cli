import assert from "node:assert/strict";

export function publishingMetadata(repository) {
  assert.match(repository ?? "", /^[A-Za-z0-9][A-Za-z0-9-]*\/[A-Za-z0-9_.-]+$/,
    "GITHUB_REPOSITORY must be an owner/repository identifier, not a URL");
  assert(![".", ".."].includes(repository.split("/")[1]), "Repository name must not be a path segment");
  const url = `https://github.com/${repository}`;
  return {
    repository: { type: "git", url: `git+${url}.git` },
    homepage: `${url}#readme`,
    bugs: `${url}/issues`,
  };
}
