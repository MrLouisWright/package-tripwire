import test from 'node:test';
import assert from 'node:assert/strict';
import { findDisallowedInstallScripts, isScriptAllowed, allowScriptsPolicy } from '../src/allowScripts.js';
import { analyze, parseAny } from '../src/index.js';
import { lock, mockRegistry, NOW } from './helpers.js';

test('isScriptAllowed supports globs', () => {
  assert.ok(isScriptAllowed('esbuild', ['esbuild']));
  assert.ok(isScriptAllowed('@scope/pkg', ['@scope/*']));
  assert.ok(!isScriptAllowed('left-pad', ['esbuild']));
});

test('findDisallowedInstallScripts lists packages outside the allowlist', async () => {
  const head = parseAny(lock([
    { name: 'esbuild', version: '1.0.0', hasInstallScript: true },
    { name: 'left-pad', version: '1.0.0', hasInstallScript: true },
  ]));
  const bad = await findDisallowedInstallScripts(head, { allowScripts: ['esbuild'], registry: null });
  assert.deepEqual(bad.map((b) => b.name), ['left-pad']);
});

test('enforceAllowScripts fails CI for disallowed scripts', async () => {
  const head = parseAny(lock([{ name: 'esbuild', version: '0.24.0', hasInstallScript: true }]));
  const r = await analyze(new Map(), head, {
    registry: mockRegistry(),
    now: NOW,
    config: { enforceAllowScripts: true, allowScripts: ['node-gyp-only'] },
  });
  assert.ok(r.findings.some((f) => f.rule === 'disallowed-install-script' && f.package === 'esbuild'));
});

test('allowScriptsPolicy serializes config', () => {
  assert.deepEqual(allowScriptsPolicy(['a', 'b']).allowScripts, ['a', 'b']);
});
