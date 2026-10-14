#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import esbuild from 'esbuild';
import { execFileSync } from 'node:child_process';

const root = path.dirname(fileURLToPath(import.meta.url)) + '/..';
const dist = path.join(root, 'dist');
fs.mkdirSync(dist, { recursive: true });

const entry = path.join(root, 'src/index.js');
const shared = { entryPoints: [entry], bundle: true, platform: 'node', target: 'node18', sourcemap: true, legalComments: 'none' };

await esbuild.build({ ...shared, outfile: path.join(dist, 'index.js'), format: 'esm' });
await esbuild.build({ ...shared, outfile: path.join(dist, 'index.cjs'), format: 'cjs' });

execFileSync(process.execPath, [
  path.join(root, 'node_modules/typescript/bin/tsc'),
  '-p', path.join(root, 'tsconfig.build.json'),
], { stdio: 'inherit', cwd: root });

console.log('build: dist/index.js, dist/index.cjs, dist/index.d.ts');
