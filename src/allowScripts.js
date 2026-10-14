// Enforceable install-script allowlist (LavaMoat allow-scripts style, reporting-only hook friendly).
import { mapLimit } from './registry.js';

const HOOKS = ['preinstall', 'install', 'postinstall'];

export function installScriptsFromMeta(v) {
  const s = {};
  for (const h of HOOKS) if (v?.scripts?.[h]) s[h] = v.scripts[h];
  if (!s.install && v?.gypfile) s.install = 'node-gyp rebuild (implicit, binding.gyp)';
  return s;
}

function globToRe(g) {
  return new RegExp('^' + g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
}

/** True when package name matches any allowScripts glob (exact name or pattern). */
export function isScriptAllowed(name, allowScripts = []) {
  if (!allowScripts?.length) return false;
  for (const p of allowScripts) {
    const pat = typeof p === 'string' ? p : p.package || p.name;
    if (pat && globToRe(pat).test(name)) return true;
  }
  return false;
}

/**
 * List packages in the lockfile that run install scripts but are not on allowScripts.
 * Uses lockfile hasInstallScript plus optional registry packument for accuracy.
 * @returns {Promise<Array<{ name: string, version: string, scripts: Record<string,string>, dev: boolean }>>}
 */
export async function findDisallowedInstallScripts(head, { allowScripts = [], registry = null, includeDev = true, concurrency = 8 } = {}) {
  if (!allowScripts.length) return [];
  const targets = [...head.values()].filter((e) => (includeDev || !e.dev) && e.hasInstallScript);
  const disallowed = [];

  const checkEntry = async (e) => {
    if (isScriptAllowed(e.name, allowScripts)) return;
    let scripts = {};
    if (registry && e.source === 'registry') {
      try {
        const pack = await registry.packument(e.name);
        const v = pack?.versions?.[e.version];
        scripts = installScriptsFromMeta(v);
      } catch { /* fall through to lockfile flag */ }
    }
    if (!Object.keys(scripts).length && e.hasInstallScript) scripts = { install: '(lockfile hasInstallScript/requiresBuild)' };
    if (Object.keys(scripts).length) disallowed.push({ name: e.name, version: e.version, scripts, dev: e.dev });
  };

  if (registry) await mapLimit(targets, concurrency, checkEntry);
  else for (const e of targets) await checkEntry(e);

  disallowed.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return disallowed;
}

/**
 * Policy file shape compatible with tooling that expects an explicit allow list.
 * @param {string[]} allowScripts
 */
export function allowScriptsPolicy(allowScripts) {
  return { tool: 'package-tripwire', version: 1, allowScripts: [...allowScripts].sort() };
}
