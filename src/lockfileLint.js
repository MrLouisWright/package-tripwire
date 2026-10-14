// lockfile-lint style policy checks on resolved tarball URLs (zero deps).

const DEFAULT_ALLOWED_HOSTS = [
  'registry.npmjs.org',
  'registry.yarnpkg.com',
  'npm.pkg.github.com',
];

const DEFAULT_ALLOWED_SCHEMES = ['https:'];

/**
 * @param {import('./lockfile.js').Entry} entry
 * @param {{ allowedHosts?: string[], allowedSchemes?: string[], validatePackageNames?: boolean }} policy
 */
export function lintResolvedEntry(entry, policy = {}) {
  const findings = [];
  const resolved = entry.resolved;
  if (!resolved || !/^https?:\/\//.test(resolved)) return findings;
  let u;
  try { u = new URL(resolved); } catch { return findings; }

  const allowedSchemes = policy.allowedSchemes ?? DEFAULT_ALLOWED_SCHEMES;
  if (allowedSchemes.length && !allowedSchemes.includes(u.protocol))
    findings.push({ rule: 'disallowed-scheme', message: `${entry.name}@${entry.version}: resolved URL uses disallowed scheme ${u.protocol} (${resolved})`, details: { scheme: u.protocol, resolved } });

  const allowedHosts = policy.allowedHosts ?? DEFAULT_ALLOWED_HOSTS;
  if (allowedHosts.length) {
    const host = u.hostname.toLowerCase();
    const ok = allowedHosts.some((h) => host === h.toLowerCase() || host.endsWith('.' + h.toLowerCase()));
    if (!ok) findings.push({ rule: 'disallowed-host', message: `${entry.name}@${entry.version}: resolved host "${host}" is not in allowedHosts`, details: { host, resolved } });
  }

  if (policy.validatePackageNames !== false) {
    const mismatch = nameUrlMismatch(entry.name, resolved);
    if (mismatch) findings.push({ rule: 'name-url-mismatch', message: `${entry.name}@${entry.version}: ${mismatch}`, details: { resolved, expected: entry.name } });
  }
  return findings;
}

/** Scan every entry in the head lockfile map. */
export function lintLockfile(head, policy = {}) {
  const out = [];
  for (const entry of head.values()) {
    for (const f of lintResolvedEntry(entry, policy)) out.push({ ...f, package: entry.name, version: entry.version });
  }
  return out;
}

/**
 * lockfile-lint name rule: tarball path should reference the package name.
 * @returns {string | null} human-readable mismatch reason
 */
export function nameUrlMismatch(name, resolved) {
  const short = name.startsWith('@') ? name.slice(name.indexOf('/') + 1) : name;
  const encShort = encodeURIComponent(short);
  const encFull = encodeURIComponent(name);
  const path = resolved.replace(/#.*$/, '').split('?')[0];
  // npm layout: .../name/-/name-version.tgz or @scope/pkg/-/pkg-version.tgz
  const patterns = [
    new RegExp(`/${escapeRe(short)}/-/${escapeRe(short)}-`, 'i'),
    new RegExp(`/${escapeRe(encShort)}/-/${escapeRe(encShort)}-`, 'i'),
  ];
  if (name.startsWith('@')) {
    const scope = name.slice(0, name.indexOf('/'));
    patterns.push(new RegExp(`/${escapeRe(scope)}/${escapeRe(short)}/-/${escapeRe(short)}-`, 'i'));
    patterns.push(new RegExp(`/${escapeRe(encodeURIComponent(scope))}/${escapeRe(encShort)}/-/${escapeRe(encShort)}-`, 'i'));
    patterns.push(new RegExp(`/${escapeRe(encFull)}/-/${escapeRe(encFull)}-`, 'i'));
  }
  if (patterns.some((re) => re.test(path))) return null;
  // tolerate flat codeload/github tarball URLs only when name appears in path
  if (/github\.com|codeload\.github\.com/i.test(path) && new RegExp(escapeRe(short), 'i').test(path)) return null;
  return `package name "${name}" does not match tarball path in ${resolved}`;
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
