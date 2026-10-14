import test from 'node:test';
import assert from 'node:assert/strict';
import { lintLockfile, nameUrlMismatch } from '../src/lockfileLint.js';
import { analyze, parseAny } from '../src/index.js';
import { lock, mockRegistry, NOW } from './helpers.js';

test('nameUrlMismatch catches swapped tarball names', () => {
  assert.equal(nameUrlMismatch('lodash', 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz'), null);
  assert.match(nameUrlMismatch('lodash', 'https://registry.npmjs.org/evil/-/evil-1.0.0.tgz'), /does not match/);
  assert.equal(nameUrlMismatch('@types/node', 'https://registry.npmjs.org/@types/node/-/node-18.0.0.tgz'), null);
});

test('lintLockfile enforces hosts and schemes', () => {
  const head = parseAny(lock([
    { name: 'ok', version: '1.0.0', resolved: 'https://registry.npmjs.org/ok/-/ok-1.0.0.tgz' },
    { name: 'evil', version: '1.0.0', resolved: 'http://registry.npmjs.org/evil/-/evil-1.0.0.tgz' },
    { name: 'other', version: '1.0.0', resolved: 'https://evil.example/pkg.tgz' },
  ]));
  const findings = lintLockfile(head, { allowedHosts: ['registry.npmjs.org'], allowedSchemes: ['https:'] });
  assert.ok(findings.some((f) => f.rule === 'disallowed-scheme' && f.package === 'evil'));
  assert.ok(findings.some((f) => f.rule === 'disallowed-host' && f.package === 'other'));
});

test('analyze surfaces lockfile lint findings', async () => {
  const head = parseAny(lock([{ name: 'x', version: '1.0.0', resolved: 'https://evil.example/x/-/x-1.0.0.tgz' }]));
  const r = await analyze(new Map(), head, { registry: mockRegistry(), now: NOW, config: { lockfileLint: { allowedHosts: ['registry.npmjs.org'] } } });
  assert.ok(r.findings.some((f) => f.rule === 'disallowed-host'));
});
