import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze, parseAny, typosquatOf, isAllowed, parseDuration, formatSarif, formatText, formatMarkdown, exitCode } from '../src/index.js';
import { lock, mockRegistry, NOW } from './helpers.js';

const OFFLINE_REG = { verifySignatures: false };

const BASE = parseAny(lock([
  { name: 'left-pad', version: '1.0.0' },
  { name: 'safe-lib', version: '2.0.0' },
  { name: 'swapped', version: '1.0.0', integrity: 'sha512-original' },
]));
const HEAD = parseAny(lock([
  { name: 'left-pad', version: '1.1.0' },
  { name: 'safe-lib', version: '2.1.0' },
  { name: 'swapped', version: '1.0.0', integrity: 'sha512-tampered' },
  { name: 'expresss', version: '4.0.0' },
  { name: 'request', version: '2.88.2' },
  { name: 'esbuild', version: '0.24.0', hasInstallScript: true },
  { name: 'gitdep', version: '1.0.0', resolved: 'git+ssh://git@github.com/x/gitdep.git#abc', integrity: '' },
  { name: 'tarball', version: '1.0.0', resolved: 'https://evil.example/t.tgz' },
]));

const rulesFor = (r, pkg) => r.findings.filter((f) => f.package === pkg).map((f) => f.rule).sort();

test('flags every suspicious class', async () => {
  const r = await analyze(BASE, HEAD, { registry: mockRegistry(), now: NOW, config: OFFLINE_REG });
  assert.deepEqual(rulesFor(r, 'left-pad'), ['install-script', 'maintainer-change', 'publisher-change', 'recent-publish']);
  assert.deepEqual(rulesFor(r, 'safe-lib'), []);
  assert.deepEqual(rulesFor(r, 'swapped'), ['integrity-change']);
  assert.deepEqual(rulesFor(r, 'expresss'), ['new-dependency', 'typosquat']);
  assert.deepEqual(rulesFor(r, 'request'), ['deprecated', 'new-dependency']);
  assert.deepEqual(rulesFor(r, 'esbuild'), ['install-script', 'new-dependency']);
  assert.deepEqual(rulesFor(r, 'gitdep'), ['new-dependency', 'non-registry-source']);
  assert.deepEqual(rulesFor(r, 'tarball'), ['new-dependency', 'non-registry-source']);
  assert.equal(r.stats.added, 5);
  assert.equal(r.stats.updated, 2);
  assert.equal(r.findings[0].level, 'error');
  assert.equal(exitCode(r), 1);
});

test('registry is only queried for added/changed registry packages', async () => {
  const reg = mockRegistry();
  await analyze(BASE, HEAD, { registry: reg, now: NOW, config: OFFLINE_REG });
  assert.deepEqual(reg.calls.sort(), ['esbuild', 'expresss', 'left-pad', 'request', 'safe-lib']);
});

test('min-age is configurable', async () => {
  const r = await analyze(BASE, HEAD, { registry: mockRegistry(), now: NOW, config: { ...OFFLINE_REG, minAge: '1h' } });
  assert.ok(!r.findings.some((f) => f.rule === 'recent-publish'));
  const r2 = await analyze(BASE, HEAD, { registry: mockRegistry(), now: NOW, config: { ...OFFLINE_REG, minAge: '45d' } });
  assert.ok(r2.findings.some((f) => f.rule === 'recent-publish' && f.package === 'safe-lib'));
});

test('allowlist and rule overrides', async () => {
  const r = await analyze(BASE, HEAD, { registry: mockRegistry(), now: NOW, config: {
    ...OFFLINE_REG,
    allow: ['esbuild', { package: 'left-pad', version: '1.1.0', rules: ['recent-publish'] }, { package: 'swapped', expires: '2020-01-01' }],
    rules: { 'new-dependency': 'off', deprecated: 'error' },
  } });
  assert.deepEqual(rulesFor(r, 'esbuild'), []);
  assert.ok(!rulesFor(r, 'left-pad').includes('recent-publish'));
  assert.ok(rulesFor(r, 'left-pad').includes('install-script'));
  assert.deepEqual(rulesFor(r, 'swapped'), ['integrity-change'], 'expired allow entry ignored');
  assert.ok(!r.findings.some((f) => f.rule === 'new-dependency'));
  assert.equal(r.findings.find((f) => f.rule === 'deprecated').level, 'error');
  assert.ok(r.suppressed.length >= 2);
});

test('offline mode still catches lockfile-only signals', async () => {
  const r = await analyze(BASE, HEAD, { registry: null, now: NOW });
  const rules = new Set(r.findings.map((f) => f.rule));
  for (const x of ['integrity-change', 'typosquat', 'non-registry-source', 'install-script', 'new-dependency']) assert.ok(rules.has(x), x);
  assert.ok(!rules.has('publisher-change'));
});

test('lockfile integrity that disagrees with the registry', async () => {
  const b = parseAny(lock([]));
  const h = parseAny(lock([{ name: 'swapped', version: '1.0.0', integrity: 'sha512-LOCAL' }]));
  const r = await analyze(b, h, { registry: mockRegistry(), now: NOW, config: OFFLINE_REG });
  assert.ok(rulesFor(r, 'swapped').includes('integrity-change'));
});

test('unknown packages and registry errors are reported, not thrown', async () => {
  const h = parseAny(lock([{ name: 'ghost-pkg-zzz', version: '1.0.0' }, { name: 'boom', version: '1.0.0' }]));
  const reg = { packument: async (n) => { if (n === 'boom') throw new Error('ECONNRESET'); return null; } };
  const r = await analyze(new Map(), h, { registry: reg, now: NOW });
  assert.ok(rulesFor(r, 'ghost-pkg-zzz').includes('unknown-package'));
  assert.ok(rulesFor(r, 'boom').includes('registry-error'));
});

test('no changes → clean', async () => {
  const r = await analyze(BASE, BASE, { registry: mockRegistry(), now: NOW, config: OFFLINE_REG });
  assert.equal(r.findings.length, 0);
  assert.equal(exitCode(r), 0);
  assert.match(formatText(r), /No suspicious/);
});

test('typosquat heuristics', () => {
  assert.equal(typosquatOf('expresss').target, 'express');
  assert.equal(typosquatOf('lodahs').target, 'lodash');
  assert.equal(typosquatOf('cross_env').target, 'cross-env');
  assert.equal(typosquatOf('@evil/lodash').target, 'lodash');
  assert.equal(typosquatOf('rnongoose')?.target, 'mongoose');
  assert.equal(typosquatOf('express'), null);
  assert.equal(typosquatOf('react-router'), null);
  assert.equal(typosquatOf('preact'), null);
  assert.equal(typosquatOf('@types/react'), null);
  assert.equal(typosquatOf('my-internal', ['my-internal-lib'])?.target, undefined);
});

test('durations and allow matching', () => {
  assert.equal(parseDuration('72h'), 72 * 3600e3);
  assert.equal(parseDuration('3d'), 3 * 86400e3);
  assert.equal(parseDuration(0), 0);
  assert.throws(() => parseDuration('soon'));
  assert.ok(isAllowed(['@acme/*'], { package: '@acme/x', version: '1', rule: 'typosquat' }));
  assert.ok(isAllowed(['a@1.0.0'], { package: 'a', version: '1.0.0', rule: 'x' }));
  assert.ok(!isAllowed(['a@1.0.0'], { package: 'a', version: '1.0.1', rule: 'x' }));
});

test('SARIF and Markdown output', async () => {
  const r = await analyze(BASE, HEAD, { registry: mockRegistry(), now: NOW, config: OFFLINE_REG });
  const s = JSON.parse(formatSarif(r, { version: '1.0.0' }));
  assert.equal(s.version, '2.1.0');
  assert.equal(s.runs[0].results.length, r.findings.length);
  assert.ok(s.runs[0].tool.driver.rules.some((x) => x.id === 'typosquat'));
  assert.ok(['error', 'warning', 'note'].includes(s.runs[0].results[0].level));
  assert.match(formatMarkdown(r), /\| 🔴 \| `install-script` \|/);
});
