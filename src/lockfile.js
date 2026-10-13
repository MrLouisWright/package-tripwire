// Lockfile parsers: package-lock.json / npm-shrinkwrap.json (v1-v3), pnpm-lock.yaml (v5-v9), yarn.lock (v1 + berry).
// All return Map<"name@version", Entry> where Entry = { name, version, resolved, integrity, hasInstallScript, dev, source }.
import fs from 'node:fs';
import path from 'node:path';

export const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'];

export function detectLockfile(dir = '.') {
  for (const f of LOCKFILES) if (fs.existsSync(path.join(dir, f))) return path.join(dir, f);
  return null;
}

export function lockfileType(file) {
  const b = path.basename(file);
  if (b.endsWith('.json')) return 'npm';
  if (b.startsWith('pnpm')) return 'pnpm';
  if (b.startsWith('yarn')) return 'yarn';
  throw new Error(`Unsupported lockfile: ${file}`);
}

export function parseLockfile(text, type) {
  if (type === 'npm') return parseNpm(text);
  if (type === 'pnpm') return parsePnpm(text);
  if (type === 'yarn') return parseYarn(text);
  if (type === 'baseline') return fromBaseline(JSON.parse(text));
  throw new Error(`Unknown lockfile type ${type}`);
}

/** Auto-detect from content (used for baselines and git blobs). */
export function parseAny(text, hintFile) {
  const t = text.trimStart();
  if (t.startsWith('{')) {
    const j = JSON.parse(text);
    if (j.tool === 'package-tripwire') return fromBaseline(j);
    return parseNpm(text);
  }
  if (/^lockfileVersion:/m.test(text)) return parsePnpm(text);
  if (/^# yarn lockfile|^__metadata:/m.test(text) || (hintFile && hintFile.endsWith('yarn.lock'))) return parseYarn(text);
  return parseLockfile(text, lockfileType(hintFile || 'package-lock.json'));
}

function add(map, e) {
  if (!e.name || !e.version) return;
  const key = `${e.name}@${e.version}`;
  const prev = map.get(key);
  if (prev) {
    prev.dev = prev.dev && e.dev;
    if (!prev.integrity && e.integrity) prev.integrity = e.integrity;
    if (!prev.resolved && e.resolved) prev.resolved = e.resolved;
    prev.hasInstallScript ||= e.hasInstallScript;
    return;
  }
  map.set(key, { name: e.name, version: e.version, resolved: e.resolved || null, integrity: e.integrity || null,
    hasInstallScript: !!e.hasInstallScript, dev: !!e.dev, source: classifySource(e.resolved, e.version) });
}

export function classifySource(resolved, version = '') {
  const r = resolved || '';
  const v = String(version);
  if (/^(git\+|git:|github:|gitlab:|bitbucket:)/.test(r) || /^(git\+|git:|github:)/.test(v) || /\.git(#|$)/.test(r)) return 'git';
  if (/^(file:|link:|workspace:|portal:)/.test(r) || /^(file:|link:)/.test(v)) return 'file';
  if (/^https?:\/\//.test(r)) {
    if (/^https?:\/\/(registry\.npmjs\.org|registry\.yarnpkg\.com|npm\.pkg\.github\.com)\//.test(r)) return 'registry';
    if (/\/-\/[^/]+\.tgz(#|$|\?)/.test(r)) return 'registry'; // custom registry tarball layout
    return 'url';
  }
  if (/^https?:\/\//.test(v)) return 'url';
  return 'registry';
}

function nameFromPath(p) {
  const i = p.lastIndexOf('node_modules/');
  return i === -1 ? null : p.slice(i + 13);
}

function parseNpm(text) {
  const j = JSON.parse(text);
  const map = new Map();
  if (j.packages) {
    for (const [p, v] of Object.entries(j.packages)) {
      if (p === '' || v.link) continue;
      const name = v.name || nameFromPath(p);
      if (!name) continue; // workspace folder
      add(map, { name, version: v.version, resolved: v.resolved, integrity: v.integrity, hasInstallScript: v.hasInstallScript, dev: v.dev });
    }
  } else if (j.dependencies) {
    const walk = (deps) => {
      for (const [name, v] of Object.entries(deps)) {
        let version = v.version;
        let resolved = v.resolved;
        if (/^(git|github:|https?:|file:)/.test(version || '')) { resolved = resolved || version; version = v.version; }
        add(map, { name, version, resolved, integrity: v.integrity, dev: v.dev });
        if (v.dependencies) walk(v.dependencies);
      }
    };
    walk(j.dependencies);
  }
  return map;
}

// ---- pnpm: minimal indentation-based reader for the `packages:` section ----
function unquote(s) {
  s = s.trim();
  if ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith('"') && s.endsWith('"'))) return s.slice(1, -1);
  return s;
}

function splitPnpmKey(key) {
  // v9: "name@1.0.0", "@s/n@1.0.0(peer@1)"; v6: "/name@1.0.0"; v5: "/name/1.0.0", "/@s/n/1.0.0_peer"
  key = unquote(key).replace(/\(.*$/, '');
  let slashFormat = false;
  if (key.startsWith('/')) { key = key.slice(1); slashFormat = true; }
  const scopeEnd = key.startsWith('@') ? key.indexOf('/') + 1 : 0;
  if (slashFormat) {
    const i = key.indexOf('/', scopeEnd);
    const at0 = key.indexOf('@', Math.max(1, scopeEnd));
    if (i !== -1 && (at0 === -1 || i < at0)) return { name: key.slice(0, i), version: key.slice(i + 1).replace(/_.*$/, '') };
  }
  const at = key.indexOf('@', Math.max(1, scopeEnd));
  if (at !== -1) return { name: key.slice(0, at), version: key.slice(at + 1).replace(/_.*$/, '') };
  return { name: key, version: '' };
}

function parsePnpm(text) {
  const map = new Map();
  const lines = text.split(/\r?\n/);
  let inPackages = false;
  let cur = null;
  let sub = null;
  const flush = () => { if (cur) add(map, cur); cur = null; };
  for (const raw of lines) {
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (indent === 0) { flush(); inPackages = line === 'packages:'; continue; }
    if (!inPackages) continue;
    if (indent === 2 && line.endsWith(':')) {
      flush();
      const { name, version } = splitPnpmKey(line.slice(0, -1));
      cur = { name, version, dev: false };
      sub = null;
      continue;
    }
    if (!cur) continue;
    if (indent === 4) {
      sub = null;
      const m = line.match(/^([A-Za-z]+):\s*(.*)$/);
      if (!m) continue;
      const [, k, v] = m;
      if (k === 'resolution') {
        if (v.startsWith('{')) parseInlineResolution(v, cur);
        else sub = 'resolution';
      } else if (k === 'requiresBuild' && v === 'true') cur.hasInstallScript = true;
      else if (k === 'dev' && v === 'true') cur.dev = true;
      else if (k === 'name') cur.name = unquote(v);
      else if (k === 'version') cur.version = unquote(v);
    } else if (indent >= 6 && sub === 'resolution') {
      const m = line.match(/^([A-Za-z]+):\s*(.*)$/);
      if (m) applyResolution(m[1], unquote(m[2]), cur);
    }
  }
  flush();
  // git/tarball versions in pnpm look like "github.com/x/y/sha" or "https://..."
  for (const e of map.values()) if (e.source === 'registry' && /^(https?:|github\.com\/|codeload\.)/.test(e.version)) e.source = /^https?:/.test(e.version) ? 'url' : 'git';
  return map;
}

function parseInlineResolution(v, cur) {
  for (const part of v.replace(/^\{|\}$/g, '').split(',')) {
    const i = part.indexOf(':');
    if (i === -1) continue;
    applyResolution(part.slice(0, i).trim(), unquote(part.slice(i + 1)), cur);
  }
}
function applyResolution(k, v, cur) {
  if (k === 'integrity') cur.integrity = v;
  else if (k === 'tarball') cur.resolved = v;
  else if (k === 'repo') cur.resolved = `git+${v}`;
  else if (k === 'commit' && cur.resolved) cur.resolved += `#${v}`;
  else if (k === 'type' && v === 'git' && !cur.resolved) cur.resolved = 'git+unknown';
  else if (k === 'directory') cur.resolved = `file:${v}`;
}

// ---- yarn v1 and berry ----
function parseYarn(text) {
  const map = new Map();
  const berry = /^__metadata:/m.test(text);
  const lines = text.split(/\r?\n/);
  let cur = null;
  const flush = () => { if (cur && !cur.skip) add(map, cur); cur = null; };
  for (const raw of lines) {
    if (!raw.trim() || raw.startsWith('#')) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (indent === 0) {
      flush();
      if (line.startsWith('__metadata')) continue;
      const first = unquote(line.replace(/:$/, '').split(/,\s*/)[0]);
      const at = first.indexOf('@', 1);
      const name = at === -1 ? first : first.slice(0, at);
      const range = at === -1 ? '' : first.slice(at + 1);
      cur = { name, range };
      continue;
    }
    if (!cur || indent !== 2) continue;
    const m = berry ? line.match(/^([A-Za-z]+):\s*(.*)$/) : line.match(/^([A-Za-z]+)\s+(.*)$/);
    if (!m) continue;
    const k = m[1];
    const v = unquote(m[2]);
    if (k === 'version') cur.version = v;
    else if (k === 'resolved') cur.resolved = v;
    else if (k === 'integrity') cur.integrity = v;
    else if (k === 'checksum') cur.integrity = `yarn-checksum:${v}`;
    else if (k === 'resolution') {
      const rs = v.slice(v.indexOf('@', 1) + 1);
      if (rs.startsWith('npm:')) { /* registry */ } else if (rs.startsWith('workspace:') || rs.startsWith('link:') || rs.startsWith('portal:')) cur.skip = true;
      else cur.resolved = rs.replace(/^patch:.*$/, '') || null;
    } else if (k === 'linkType' && v === 'soft') cur.skip = true;
  }
  flush();
  for (const [k, e] of map) {
    if (e.name.startsWith('__')) map.delete(k);
  }
  // berry: drop workspace/soft-linked entries (they came through with skip flag lost) – re-parse cheaply
  if (berry) {
    for (const [k, e] of [...map]) if (/0\.0\.0-use\.local/.test(e.version)) map.delete(k);
  }
  return map;
}

// ---- baseline snapshots ----
export function toBaseline(map, meta = {}) {
  return {
    tool: 'package-tripwire', format: 1, createdAt: new Date().toISOString(), ...meta,
    packages: [...map.values()].sort((a, b) => (a.name + a.version).localeCompare(b.name + b.version))
      .map(({ name, version, resolved, integrity, hasInstallScript, dev }) => ({ name, version, resolved, integrity, hasInstallScript, dev })),
  };
}

function fromBaseline(j) {
  const map = new Map();
  for (const p of j.packages || []) add(map, p);
  return map;
}
