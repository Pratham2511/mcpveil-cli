// The source shrinkwrap intentionally includes contributor tooling. Publishing
// the source directory would install extraneous tools for normal npm consumers.
throw new Error('Publish a GitHub release for trusted publishing, or publish the tested tarball from npm run pack:release. Direct source-directory publication is disabled.');
