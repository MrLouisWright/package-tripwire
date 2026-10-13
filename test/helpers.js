export const NOW = Date.parse('2026-10-13T12:00:00Z');
const day = 86400e3;
const iso = (ms) => new Date(ms).toISOString();

export function lock(pkgs) {
  const packages = { '': { name: 'app', version: '1.0.0' } };
  for (const p of pkgs) packages[`node_modules/${p.name}`] = { version: p.version, resolved: p.resolved ?? `https://registry.npmjs.org/${p.name}/-/${p.name.split('/').pop()}-${p.version}.tgz`, integrity: p.integrity ?? `sha512-${p.name}-${p.version}`, ...(p.hasInstallScript ? { hasInstallScript: true } : {}), ...(p.dev ? { dev: true } : {}) };
  return JSON.stringify({ name: 'app', lockfileVersion: 3, requires: true, packages }, null, 2);
}

export const PACKUMENTS = {
  'left-pad': {
    time: { '1.0.0': iso(NOW - 900 * day), '1.1.0': iso(NOW - 3 * 3600e3) },
    versions: {
      '1.0.0': { _npmUser: { name: 'alice' }, maintainers: [{ name: 'alice' }], dist: { integrity: 'sha512-left-pad-1.0.0' } },
      '1.1.0': { _npmUser: { name: 'mallory' }, maintainers: [{ name: 'alice' }, { name: 'mallory' }], scripts: { postinstall: 'node steal.js' }, dist: { integrity: 'sha512-left-pad-1.1.0' } },
    },
  },
  'safe-lib': {
    time: { '2.0.0': iso(NOW - 400 * day), '2.1.0': iso(NOW - 30 * day) },
    versions: {
      '2.0.0': { _npmUser: { name: 'bob' }, maintainers: [{ name: 'bob' }], dist: { integrity: 'sha512-safe-lib-2.0.0' } },
      '2.1.0': { _npmUser: { name: 'bob' }, maintainers: [{ name: 'bob' }], dist: { integrity: 'sha512-safe-lib-2.1.0' } },
    },
  },
  'expresss': {
    time: { '4.0.0': iso(NOW - 100 * day) },
    versions: { '4.0.0': { _npmUser: { name: 'eve' }, maintainers: [{ name: 'eve' }], dist: { integrity: 'sha512-expresss-4.0.0' } } },
  },
  'request': {
    time: { '2.88.2': iso(NOW - 2000 * day) },
    versions: { '2.88.2': { _npmUser: { name: 'mikeal' }, maintainers: [{ name: 'mikeal' }], deprecated: 'request has been deprecated', dist: { integrity: 'sha512-request-2.88.2' } } },
  },
  'esbuild': {
    time: { '0.24.0': iso(NOW - 60 * day) },
    versions: { '0.24.0': { _npmUser: { name: 'evanw' }, maintainers: [{ name: 'evanw' }], scripts: { postinstall: 'node install.js' }, dist: { integrity: 'sha512-esbuild-0.24.0' } } },
  },
  'swapped': {
    time: { '1.0.0': iso(NOW - 60 * day) },
    versions: { '1.0.0': { _npmUser: { name: 'x' }, maintainers: [{ name: 'x' }], dist: { integrity: 'sha512-REGISTRYVALUE' } } },
  },
};

export function mockRegistry(extra = {}) {
  const all = { ...PACKUMENTS, ...extra };
  const calls = [];
  return { calls, packument: async (n) => { calls.push(n); return all[n] ?? null; } };
}
