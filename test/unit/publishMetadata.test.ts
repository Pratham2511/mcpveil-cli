import { it, expect } from "vitest";
import { publishingMetadata } from "../../scripts/publish-metadata.mjs";

it("derives release metadata from the repository context without a personal author", () => {
  expect(publishingMetadata("example-org/example-repo")).toEqual({
    repository: { type: "git", url: "git+https://github.com/example-org/example-repo.git" },
    homepage: "https://github.com/example-org/example-repo#readme",
    bugs: "https://github.com/example-org/example-repo/issues",
  });
});

it.each([undefined, "", "https://github.com/example-org/example-repo", "example-org", "../repo", "owner/repo/extra"])(
  "rejects invalid repository context %s", (repository) => {
    expect(() => publishingMetadata(repository)).toThrow();
  }
);
