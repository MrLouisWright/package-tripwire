// npm registry ECDSA signature verification and provenance detection (zero runtime deps).
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

const KEYS_TTL_MS = 3600e3;

/**
 * @typedef {{ keyid: string, key: string, expires?: string | null }} SigningKey
 */

/**
 * Fetch signing keys from `GET {registry}/-/npm/v1/keys` with optional in-memory cache.
 * @param {{ registry?: string, fetchImpl?: typeof fetch, timeoutMs?: number, cache?: { at?: number, keys?: SigningKey[] } }} opts
 */
export async function fetchSigningKeys({ registry = 'https://registry.npmjs.org', fetchImpl = globalThis.fetch, timeoutMs = 15000, cache } = {}) {
  if (cache?.keys && cache.at && Date.now() - cache.at < KEYS_TTL_MS) return cache.keys;
  const base = registry.replace(/\/+$/, '');
  const ctl = AbortSignal.timeout ? AbortSignal.timeout(timeoutMs) : undefined;
  const res = await fetchImpl(`${base}/-/npm/v1/keys`, { headers: { accept: 'application/json', 'user-agent': 'package-tripwire' }, signal: ctl });
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching signing keys from ${base}`);
  const j = await res.json();
  const keys = (j.keys || []).filter((k) => k.keytype === 'ecdsa-sha2-nistp256' && k.key);
  if (cache) { cache.keys = keys; cache.at = Date.now(); }
  return keys;
}

/** Whether registry metadata includes an SLSA / npm provenance attestation. */
export function hasProvenance(versionMeta) {
  const a = versionMeta?.dist?.attestations;
  if (!a) return false;
  if (a.provenance && (a.provenance.predicateType || a.provenance._type || Object.keys(a.provenance).length)) return true;
  if (typeof a.url === 'string' && /attestations?/i.test(a.url)) return true;
  return false;
}

/**
 * Verify dist.signatures against registry keys.
 * @returns {'valid' | 'missing' | 'invalid' | 'unsupported' | 'no-integrity'}
 */
export function verifyDistSignature(name, version, dist, keys, now = Date.now()) {
  if (!dist?.integrity) return 'no-integrity';
  const sigs = dist.signatures;
  if (!sigs?.length) return 'missing';
  const message = Buffer.from(`${name}@${version}:${dist.integrity}`, 'utf8');
  for (const sig of sigs) {
    const keyRec = keys.find((k) => k.keyid === sig.keyid);
    if (!keyRec) continue;
    if (keyRec.expires && Date.parse(keyRec.expires) < now) continue;
    try {
      const pub = createPublicKey({ key: Buffer.from(keyRec.key, 'base64'), format: 'der', type: 'spki' });
      if (cryptoVerify('sha256', message, { key: pub, dsaEncoding: 'der' }, Buffer.from(sig.sig, 'base64'))) return 'valid';
    } catch { /* try next key */ }
  }
  return keys.length ? 'invalid' : 'unsupported';
}
