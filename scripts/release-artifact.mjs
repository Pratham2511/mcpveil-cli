import { cpSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, isAbsolute } from 'node:path';
/** Create a distribution staging tree; never mutate the development lockfile. */
export function stageRelease(root, destination) {
  const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const lock = JSON.parse(readFileSync(join(root, 'npm-shrinkwrap.json'), 'utf8'));
  mkdirSync(destination, { recursive: true });
  for (const name of manifest.files) {
    const path = relative(root, join(root, name));
    if (isAbsolute(path) || path.startsWith('..')) throw new Error('Distribution file escapes package root');
    cpSync(join(root, name), join(destination, name), { recursive: true });
  }
  delete manifest.devDependencies;
  delete manifest.scripts;
  // npm can install development entries embedded in a CLI shrinkwrap even as
  // a transitive package. Keep the shipped lock limited to runtime dependencies.
  lock.packages = Object.fromEntries(Object.entries(lock.packages).filter(([path, entry]) => path === '' || !entry.dev));
  delete lock.packages[''].devDependencies;
  writeFileSync(join(destination, 'package.json'), JSON.stringify(manifest, null, 2) + '\n');
  writeFileSync(join(destination, 'npm-shrinkwrap.json'), JSON.stringify(lock, null, 2) + '\n');
}
