import { readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { spawnSync } from 'node:child_process';
const root = resolve(import.meta.dirname, '..');
function files(directory) { return readdirSync(directory, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? files(join(directory, entry.name)) : entry.name.endsWith('.mjs') ? [join(directory, entry.name)] : []); }
for (const file of ['src', 'public', 'scripts', 'test'].flatMap(directory => files(join(root, directory)))) {
  const result = spawnSync(process.execPath, ['--check', file], { stdio: 'inherit' }); if (result.status !== 0) process.exit(result.status || 1);
}
console.log('JavaScript syntax checks passed.');
