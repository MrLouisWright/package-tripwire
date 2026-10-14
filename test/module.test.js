import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url)) + '/..';

test('ESM import from built dist', async () => {
  const mod = await import(path.join(root, 'dist/index.js'));
  assert.equal(typeof mod.analyze, 'function');
  assert.equal(typeof mod.verifyDistSignature, 'function');
  assert.equal(typeof mod.lintLockfile, 'function');
});

test('CJS require from built dist', () => {
  const req = createRequire(import.meta.url);
  const mod = req(path.join(root, 'dist/index.cjs'));
  assert.equal(typeof mod.analyze, 'function');
  assert.ok(mod.RULES && typeof mod.RULES === 'object');
});
