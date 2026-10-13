import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync, execFileSync } from 'node:child_process';
import { lock } from './helpers.js';

const BIN = path.resolve('bin/package-tripwire.js');
const cli = (args, cwd) => spawnSync(process.execPath, [BIN, ...args], { cwd, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '' } });

function repo() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'pt-'));
  const g = (...a) => execFileSync('git', a, { cwd: d, stdio: 'ignore' });
  g('init', '-q'); g('config', 'user.email', 't@t'); g('config', 'user.name', 't');
  fs.writeFileSync(path.join(d, 'package-lock.json'), lock([{ name: 'a', version: '1.0.0' }]));
  g('add', '.'); g('commit', '-qm', 'base');
  return d;
}

test('help and version', () => {
  assert.match(cli(['--help']).stdout, /--baseline/);
  assert.match(cli(['--version']).stdout, /^\d+\.\d+\.\d+/);
  assert.equal(cli(['--bogus']).status, 2);
});

test('git base ref: clean and dirty', () => {
  const d = repo();
  let r = cli(['--offline'], d);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /No suspicious/);
  fs.writeFileSync(path.join(d, 'package-lock.json'), lock([{ name: 'a', version: '1.0.0', integrity: 'sha512-evil' }, { name: 'lodahs', version: '1.0.0' }]));
  r = cli(['--offline', '--base', 'HEAD', '--sarif', 'out.sarif', '--json', 'out.json', '--markdown', 'out.md'], d);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /\[typosquat\] lodahs/);
  assert.match(r.stdout, /\[integrity-change\] a@1.0.0/);
  const j = JSON.parse(fs.readFileSync(path.join(d, 'out.json'), 'utf8'));
  assert.equal(j.exitCode, 1);
  assert.equal(JSON.parse(fs.readFileSync(path.join(d, 'out.sarif'), 'utf8')).version, '2.1.0');
  assert.match(fs.readFileSync(path.join(d, 'out.md'), 'utf8'), /typosquat/);
  assert.equal(cli(['--offline', '--fail-on', 'none'], d).status, 0);
});

test('json to stdout and fail-on warn', () => {
  const d = repo();
  fs.writeFileSync(path.join(d, 'package-lock.json'), lock([{ name: 'a', version: '1.0.0' }, { name: 'g', version: '1.0.0', resolved: 'git+https://github.com/x/g.git#1' }]));
  let r = cli(['--offline', '--json'], d);
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout).findings.find((f) => f.rule === 'non-registry-source').package, 'g');
  r = cli(['--offline', '--fail-on', 'warn'], d);
  assert.equal(r.status, 1);
});

test('baseline mode + allowlist config', () => {
  const d = repo();
  assert.equal(cli(['--save-baseline', '.tripwire/baseline.json'], d).status, 0);
  fs.writeFileSync(path.join(d, 'package-lock.json'), lock([{ name: 'a', version: '1.0.0' }, { name: 'expresss', version: '1.0.0' }]));
  assert.equal(cli(['--offline', '--baseline', '.tripwire/baseline.json'], d).status, 1);
  fs.writeFileSync(path.join(d, '.package-tripwire.json'), JSON.stringify({ allow: [{ package: 'expresss', reason: 'internal fork' }] }));
  const r = cli(['--offline', '--baseline', '.tripwire/baseline.json'], d);
  assert.equal(r.status, 0, r.stdout);
  assert.match(r.stdout, /allowlisted/);
});

test('missing lockfile → exit 2', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'pt-'));
  assert.equal(cli(['--offline'], d).status, 2);
});
