import fs from 'node:fs';
import path from 'node:path';

export const RULES = {
  'install-script': { level: 'error', title: 'New or changed install script' },
  'disallowed-install-script': { level: 'error', title: 'Install script not on allowScripts list' },
  'integrity-change': { level: 'error', title: 'Tarball/integrity changed for the same version' },
  'registry-signature-invalid': { level: 'error', title: 'Registry tarball signature is invalid' },
  'unsigned-package': { level: 'warn', title: 'Registry package is missing a signature' },
  'provenance-lost': { level: 'error', title: 'Provenance attestation disappeared between versions' },
  'provenance-missing': { level: 'note', title: 'Version has no provenance attestation' },
  'disallowed-host': { level: 'error', title: 'Resolved tarball host is not allowed' },
  'disallowed-scheme': { level: 'error', title: 'Resolved tarball URL scheme is not allowed' },
  'name-url-mismatch': { level: 'error', title: 'Package name does not match resolved tarball URL' },
  'typosquat': { level: 'error', title: 'Name resembles a popular package' },
  'publisher-change': { level: 'error', title: 'Version published by a different npm user' },
  'recent-publish': { level: 'error', title: 'Version published very recently' },
  'non-registry-source': { level: 'warn', title: 'Git, URL or file dependency' },
  'maintainer-change': { level: 'warn', title: 'Maintainer list changed' },
  'deprecated': { level: 'warn', title: 'Deprecated version' },
  'new-dependency': { level: 'note', title: 'Newly added package' },
  'unknown-package': { level: 'warn', title: 'Package not found in registry' },
  'registry-error': { level: 'warn', title: 'Registry lookup failed' },
};

export const CONFIG_FILES = ['.package-tripwire.json', '.package-tripwirerc.json', '.package-tripwirerc'];

export const LOCKFILE_LINT_DEFAULTS = {
  allowedHosts: ['registry.npmjs.org', 'registry.yarnpkg.com', 'npm.pkg.github.com'],
  allowedSchemes: ['https:'],
  validatePackageNames: true,
};

export const DEFAULTS = {
  minAge: '72h',
  registry: 'https://registry.npmjs.org',
  failOn: 'error',
  rules: {},
  allow: [],
  popular: [],
  includeDev: true,
  concurrency: 8,
  verifySignatures: true,
  requireProvenance: false,
  lockfileLint: false,
  allowScripts: [],
  enforceAllowScripts: false,
};

export function loadConfig(dir = '.', explicit) {
  let cfg = {};
  if (explicit) cfg = JSON.parse(fs.readFileSync(explicit, 'utf8'));
  else {
    const f = CONFIG_FILES.map((c) => path.join(dir, c)).find((p) => fs.existsSync(p));
    if (f) cfg = JSON.parse(fs.readFileSync(f, 'utf8'));
    else {
      const pj = path.join(dir, 'package.json');
      if (fs.existsSync(pj)) { try { cfg = JSON.parse(fs.readFileSync(pj, 'utf8'))['package-tripwire'] || {}; } catch { /* ignore */ } }
    }
  }
  return {
    ...DEFAULTS,
    ...cfg,
    rules: { ...DEFAULTS.rules, ...(cfg.rules || {}) },
    lockfileLint: cfg.lockfileLint === false || !cfg.lockfileLint ? false : { ...LOCKFILE_LINT_DEFAULTS, ...cfg.lockfileLint },
  };
}

/** Parse "72h", "3d", "90m", "1w" or a number of hours into milliseconds. */
export function parseDuration(v) {
  if (typeof v === 'number') return v * 3600e3;
  const m = String(v).trim().match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?$/i);
  if (!m) throw new Error(`Invalid duration: ${v}`);
  const mult = { ms: 1, s: 1e3, m: 60e3, h: 3600e3, d: 86400e3, w: 604800e3 }[(m[2] || 'h').toLowerCase()];
  return Number(m[1]) * mult;
}

function globToRe(g) {
  return new RegExp('^' + g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
}

/**
 * Allow entries: "name", "name@1.2.3", "@scope/*", or { package, version?, rules?, reason?, expires? }.
 */
export function isAllowed(allow, finding, now = Date.now()) {
  for (const a of allow || []) {
    const e = typeof a === 'string' ? splitSpec(a) : { ...splitSpec(a.package || a.name || ''), ...(a.version ? { version: a.version } : {}), rules: a.rules, expires: a.expires };
    if (!e.package || !globToRe(e.package).test(finding.package)) continue;
    if (e.version && e.version !== '*' && e.version !== finding.version) continue;
    if (e.rules && e.rules.length && !e.rules.includes(finding.rule)) continue;
    if (e.expires && Date.parse(e.expires) < now) continue;
    return true;
  }
  return false;
}

function splitSpec(s) {
  const at = s.indexOf('@', 1);
  return at === -1 ? { package: s } : { package: s.slice(0, at), version: s.slice(at + 1) };
}
