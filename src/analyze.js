import { RULES, isAllowed, parseDuration } from './config.js';
import { typosquatOf, POPULAR } from './typosquat.js';
import { mapLimit } from './registry.js';
import { hasProvenance, verifyDistSignature } from './signatures.js';
import { lintLockfile } from './lockfileLint.js';
import { findDisallowedInstallScripts, installScriptsFromMeta as installScripts } from './allowScripts.js';

const HOOKS = ['preinstall', 'install', 'postinstall'];

const names = (arr) => (arr || []).map((m) => (typeof m === 'string' ? m.replace(/\s*<.*$/, '') : m.name)).filter(Boolean).sort();

function cmpVer(a, b) {
  const pa = String(a).split(/[.+-]/).map((x) => (isNaN(x) ? x : Number(x)));
  const pb = String(b).split(/[.+-]/).map((x) => (isNaN(x) ? x : Number(x)));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if (pa[i] === pb[i]) continue;
    if (pa[i] === undefined) return -1;
    if (pb[i] === undefined) return 1;
    return typeof pa[i] === typeof pb[i] ? (pa[i] < pb[i] ? -1 : 1) : (typeof pa[i] === 'number' ? -1 : 1);
  }
  return 0;
}

/**
 * Compare two lockfile maps and return findings.
 * @param {Map} base  @param {Map} head
 * @param {{registry?:{packument:Function}, config?:object, now?:number, lockfile?:string}} opts
 */
export async function analyze(base, head, { registry, config = {}, now = Date.now(), lockfile = 'package-lock.json' } = {}) {
  const minAgeMs = parseDuration(config.minAge ?? '72h');
  const popular = [...POPULAR, ...(config.popular || [])];
  const findings = [];
  const level = (rule) => config.rules?.[rule] ?? RULES[rule].level;
  const push = (f) => {
    const lv = level(f.rule);
    if (lv === 'off') return;
    findings.push({ level: lv, title: RULES[f.rule].title, lockfile, ...f });
  };

  const keep = (e) => config.includeDev !== false || !e.dev;
  const baseByName = new Map();
  for (const e of base.values()) { if (!baseByName.has(e.name)) baseByName.set(e.name, []); baseByName.get(e.name).push(e); }

  if (config.lockfileLint && config.lockfileLint !== false) {
    for (const lf of lintLockfile(head, config.lockfileLint)) {
      const ent = head.get(`${lf.package}@${lf.version}`);
      if (ent && !keep(ent)) continue;
      push({ rule: lf.rule, package: lf.package, version: lf.version, message: lf.message, details: lf.details || {} });
    }
  }

  if (config.enforceAllowScripts && config.allowScripts?.length) {
    const bad = await findDisallowedInstallScripts(head, {
      allowScripts: config.allowScripts,
      registry: registry || null,
      includeDev: config.includeDev !== false,
      concurrency: config.concurrency || 8,
    });
    for (const b of bad) {
      const what = Object.entries(b.scripts).map(([k, v]) => `${k}: ${v}`).join('; ');
      push({ rule: 'disallowed-install-script', package: b.name, version: b.version, message: `${b.name}@${b.version} runs install scripts but is not in allowScripts → ${what}`, details: { scripts: b.scripts } });
    }
  }

  let signingKeys = null;
  if (registry && config.verifySignatures !== false && typeof registry.signingKeys === 'function') {
    try { signingKeys = await registry.signingKeys(); } catch (e) {
      push({ rule: 'registry-error', package: '(registry)', version: '', message: `Could not fetch registry signing keys: ${e.message}`, details: {} });
    }
  }

  // Same name@version present on both sides: integrity / resolved must not change.
  for (const [key, h] of head) {
    const b = base.get(key);
    if (!b || !keep(h)) continue;
    if (b.integrity && h.integrity && b.integrity !== h.integrity)
      push({ rule: 'integrity-change', package: h.name, version: h.version, message: `${key}: integrity changed from ${short(b.integrity)} to ${short(h.integrity)} without a version bump`, details: { before: b.integrity, after: h.integrity } });
    else if (b.resolved && h.resolved && stripHash(b.resolved) !== stripHash(h.resolved) && (b.source !== 'registry' || h.source !== 'registry' || host(b.resolved) !== host(h.resolved)))
      push({ rule: 'integrity-change', package: h.name, version: h.version, message: `${key}: tarball source changed from ${b.resolved} to ${h.resolved}`, details: { before: b.resolved, after: h.resolved } });
    if (h.hasInstallScript && !b.hasInstallScript)
      push({ rule: 'install-script', package: h.name, version: h.version, message: `${key}: lockfile now marks this package as having install scripts`, details: {} });
  }

  const changed = [];
  for (const [key, h] of head) {
    if (base.has(key) || !keep(h)) continue;
    const prevs = (baseByName.get(h.name) || []).slice().sort((a, b) => cmpVer(b.version, a.version));
    const prev = prevs.find((p) => !head.has(`${p.name}@${p.version}`)) || prevs[0] || null;
    changed.push({ h, prev });
  }

  for (const { h, prev } of changed) {
    const id = `${h.name}@${h.version}`;
    if (!prev) {
      push({ rule: 'new-dependency', package: h.name, version: h.version, message: `${id} added${h.dev ? ' (dev)' : ''}`, details: { dev: h.dev } });
      const t = typosquatOf(h.name, popular);
      if (t) push({ rule: 'typosquat', package: h.name, version: h.version, message: `${h.name} looks like a typosquat: ${t.reason}`, details: t });
    }
    if (h.source !== 'registry')
      push({ rule: 'non-registry-source', package: h.name, version: h.version, previousVersion: prev?.version, message: `${id} is installed from a ${h.source} source: ${h.resolved || h.version}`, details: { source: h.source, resolved: h.resolved } });
    if (h.hasInstallScript && !prev?.hasInstallScript && !registry)
      push({ rule: 'install-script', package: h.name, version: h.version, previousVersion: prev?.version, message: `${id} has install scripts (lockfile hasInstallScript/requiresBuild)`, details: {} });
  }

  if (registry) {
    const regTargets = new Map();
    for (const { h, prev } of changed) if (h.source === 'registry') regTargets.set(`${h.name}@${h.version}`, { h, prev });
    if (config.verifySignatures !== false) {
      for (const h of head.values()) {
        if (!keep(h) || h.source !== 'registry') continue;
        const key = `${h.name}@${h.version}`;
        if (!regTargets.has(key)) {
          const prevs = (baseByName.get(h.name) || []).slice().sort((a, b) => cmpVer(b.version, a.version));
          const prev = prevs.find((p) => !head.has(`${p.name}@${p.version}`)) || prevs[0] || null;
          regTargets.set(key, { h, prev: prev && prev.source === 'registry' ? prev : null });
        }
      }
    }
    await mapLimit([...regTargets.values()], config.concurrency || 8, async ({ h, prev }) => {
      const id = `${h.name}@${h.version}`;
      let pack;
      try { pack = await registry.packument(h.name); } catch (e) {
        push({ rule: 'registry-error', package: h.name, version: h.version, message: `${id}: registry lookup failed (${e.message})`, details: {} });
        return;
      }
      const v = pack?.versions?.[h.version];
      if (!v) { push({ rule: 'unknown-package', package: h.name, version: h.version, message: `${id} not found in registry`, details: {} }); return; }
      const pv = prev && prev.source === 'registry' ? pack.versions?.[prev.version] : null;

      const now_s = installScripts(v);
      const was_s = pv ? installScripts(pv) : {};
      const diff = HOOKS.filter((k) => (now_s[k] || '') !== (was_s[k] || '') && now_s[k]);
      if (diff.length) {
        const what = diff.map((k) => `${k}: ${now_s[k]}`).join('; ');
        push({ rule: 'install-script', package: h.name, version: h.version, previousVersion: prev?.version,
          message: prev ? `${id} ${pv ? 'changes' : 'has'} install scripts vs ${prev.version} → ${what}` : `${id} runs install scripts → ${what}`, details: { scripts: now_s, previous: was_s } });
      } else if (h.hasInstallScript && !prev?.hasInstallScript && !Object.keys(now_s).length) {
        push({ rule: 'install-script', package: h.name, version: h.version, previousVersion: prev?.version, message: `${id} is marked hasInstallScript in the lockfile`, details: {} });
      }

      if (pv) {
        const a = pv._npmUser?.name, b = v._npmUser?.name;
        if (a && b && a !== b) push({ rule: 'publisher-change', package: h.name, version: h.version, previousVersion: prev.version, message: `${id} was published by "${b}" but ${prev.version} was published by "${a}"`, details: { before: a, after: b } });
        const ma = names(pv.maintainers), mb = names(v.maintainers);
        if (ma.length && mb.length && ma.join() !== mb.join()) {
          const added = mb.filter((x) => !ma.includes(x)), removed = ma.filter((x) => !mb.includes(x));
          push({ rule: 'maintainer-change', package: h.name, version: h.version, previousVersion: prev.version, message: `${id} maintainers changed${added.length ? ` +${added.join(',+')}` : ''}${removed.length ? ` -${removed.join(',-')}` : ''}`, details: { added, removed } });
        }
      }

      const t = pack.time?.[h.version];
      if (t && now - Date.parse(t) < minAgeMs) {
        const hrs = Math.max(0, (now - Date.parse(t)) / 3600e3);
        push({ rule: 'recent-publish', package: h.name, version: h.version, previousVersion: prev?.version, message: `${id} was published ${hrs < 48 ? hrs.toFixed(1) + 'h' : (hrs / 24).toFixed(1) + 'd'} ago (minimum age ${config.minAge ?? '72h'})`, details: { published: t } });
      }

      if (v.deprecated) push({ rule: 'deprecated', package: h.name, version: h.version, message: `${id} is deprecated: ${v.deprecated}`, details: { reason: v.deprecated } });

      const ri = v.dist?.integrity;
      if (ri && h.integrity && !h.integrity.startsWith('yarn-checksum:') && !h.integrity.split(/\s+/).includes(ri) && h.integrity.split('-')[0] === ri.split('-')[0])
        push({ rule: 'integrity-change', package: h.name, version: h.version, message: `${id}: lockfile integrity ${short(h.integrity)} does not match registry ${short(ri)}`, details: { lockfile: h.integrity, registry: ri } });

      if (signingKeys && v.dist) {
        const sigStatus = verifyDistSignature(h.name, h.version, v.dist, signingKeys, now);
        if (sigStatus === 'invalid')
          push({ rule: 'registry-signature-invalid', package: h.name, version: h.version, message: `${id}: registry tarball signature is invalid`, details: { signatures: v.dist.signatures } });
        else if (sigStatus === 'missing' && signingKeys.length)
          push({ rule: 'unsigned-package', package: h.name, version: h.version, message: `${id}: registry metadata has no tarball signature`, details: {} });
      }

      const nowProv = hasProvenance(v);
      const wasProv = pv ? hasProvenance(pv) : false;
      if (pv && wasProv && !nowProv)
        push({ rule: 'provenance-lost', package: h.name, version: h.version, previousVersion: prev.version, message: `${id} lost npm provenance attestation (previous ${prev.version} had provenance)`, details: {} });
      else if (config.requireProvenance && !nowProv)
        push({ rule: 'provenance-missing', package: h.name, version: h.version, previousVersion: prev?.version, message: `${id} has no provenance attestation`, details: {} });
    });
  }

  const allow = config.allow || [];
  const out = [];
  const suppressed = [];
  for (const f of findings) (isAllowed(allow, f, now) ? suppressed : out).push(f);
  const order = { error: 0, warn: 1, note: 2 };
  out.sort((a, b) => order[a.level] - order[b.level] || a.package.localeCompare(b.package) || a.rule.localeCompare(b.rule));
  return {
    findings: out, suppressed,
    stats: { base: base.size, head: head.size, added: changed.filter((c) => !c.prev).length, updated: changed.filter((c) => c.prev).length,
      removed: [...base.keys()].filter((k) => !head.has(k) && ![...head.values()].some((h) => h.name === base.get(k).name)).length },
  };
}

const short = (s) => (s && s.length > 24 ? s.slice(0, 22) + '…' : s);
const stripHash = (u) => u.replace(/#.*$/, '');
const host = (u) => { try { return new URL(u).host; } catch { return u; } };
