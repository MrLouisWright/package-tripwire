import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseAny, detectLockfile, toBaseline } from './lockfile.js';
import { analyze } from './analyze.js';
import { createRegistry } from './registry.js';
import { loadConfig } from './config.js';

export { analyze } from './analyze.js';
export { parseLockfile, parseAny, detectLockfile, toBaseline, classifySource } from './lockfile.js';
export { createRegistry } from './registry.js';
export { loadConfig, parseDuration, isAllowed, RULES, LOCKFILE_LINT_DEFAULTS } from './config.js';
export { typosquatOf, levenshtein, POPULAR } from './typosquat.js';
export { formatText, formatJson, formatSarif, formatMarkdown, exitCode } from './format.js';
export { fetchSigningKeys, hasProvenance, verifyDistSignature } from './signatures.js';
export { lintLockfile, lintResolvedEntry, nameUrlMismatch } from './lockfileLint.js';
export { findDisallowedInstallScripts, isScriptAllowed, allowScriptsPolicy, installScriptsFromMeta } from './allowScripts.js';

/** Read a file as it existed at a git ref. Returns null if it did not exist there. */
export function readAtRef(ref, file, cwd = '.') {
  const top = execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd, encoding: 'utf8' }).trim();
  const rel = path.relative(top, path.resolve(cwd, file)).split(path.sep).join('/');
  try { return execFileSync('git', ['show', `${ref}:${rel}`], { cwd: top, encoding: 'utf8', maxBuffer: 512 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) {
    const msg = String(e.stderr || e.message);
    if (/does not exist|exists on disk, but not in/.test(msg)) return null;
    throw new Error(`git show ${ref}:${rel} failed: ${msg.trim()}`);
  }
}

/** High-level entry used by the CLI. */
export async function run({ cwd = '.', lockfile, base, baseline, config: cfgOverride = {}, configPath, offline = false, registry, now } = {}) {
  const config = { ...loadConfig(cwd, configPath), ...cfgOverride };
  const lf = lockfile ? path.resolve(cwd, lockfile) : detectLockfile(cwd);
  if (!lf || !fs.existsSync(lf)) throw new Error('No lockfile found (package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock)');
  const headText = fs.readFileSync(lf, 'utf8');
  const head = parseAny(headText, lf);
  let baseMap = new Map();
  let baseLabel;
  if (baseline) {
    baseLabel = `baseline ${baseline}`;
    baseMap = fs.existsSync(path.resolve(cwd, baseline)) ? parseAny(fs.readFileSync(path.resolve(cwd, baseline), 'utf8'), lf) : new Map();
  } else {
    const ref = base || 'HEAD';
    baseLabel = `git ${ref}`;
    const t = readAtRef(ref, lf, cwd);
    if (t) baseMap = parseAny(t, lf);
  }
  const reg = offline ? null : registry || createRegistry({ registry: config.registry, token: process.env.NPM_TOKEN_READ || undefined, cacheDir: config.cacheDir });
  const rel = path.relative(path.resolve(cwd), lf).split(path.sep).join('/');
  const result = await analyze(baseMap, head, { registry: reg, config, now, lockfile: rel });
  return { ...result, failOn: config.failOn, base: baseLabel, lockfileAbs: lf, lockfile: rel, head };
}

export function saveBaseline(file, map, meta) {
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(toBaseline(map, meta), null, 2) + '\n');
}
