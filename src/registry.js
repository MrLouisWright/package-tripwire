// npm registry metadata client with in-memory + optional disk cache. Zero dependencies (global fetch, Node 18+).
import fs from 'node:fs';
import path from 'node:path';

export function createRegistry({ registry = 'https://registry.npmjs.org', token, fetchImpl = globalThis.fetch, cacheDir, timeoutMs = 15000, retries = 2 } = {}) {
  const mem = new Map();
  const base = registry.replace(/\/+$/, '');
  async function packument(name) {
    if (mem.has(name)) return mem.get(name);
    const p = (async () => {
      const file = cacheDir && path.join(cacheDir, encodeURIComponent(name) + '.json');
      if (file && fs.existsSync(file) && Date.now() - fs.statSync(file).mtimeMs < 3600e3) return JSON.parse(fs.readFileSync(file, 'utf8'));
      const url = `${base}/${name.startsWith('@') ? '@' + encodeURIComponent(name.slice(1)) : encodeURIComponent(name)}`;
      const headers = { accept: 'application/json', 'user-agent': 'package-tripwire' };
      if (token) headers.authorization = `Bearer ${token}`;
      let lastErr;
      for (let i = 0; i <= retries; i++) {
        try {
          const ctl = AbortSignal.timeout ? AbortSignal.timeout(timeoutMs) : undefined;
          const res = await fetchImpl(url, { headers, signal: ctl });
          if (res.status === 404) return null;
          if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
          const j = await res.json();
          if (file) { fs.mkdirSync(cacheDir, { recursive: true }); fs.writeFileSync(file, JSON.stringify(j)); }
          return j;
        } catch (e) { lastErr = e; if (i < retries) await new Promise((r) => setTimeout(r, 300 * (i + 1))); }
      }
      throw lastErr;
    })();
    mem.set(name, p);
    return p;
  }
  return { packument };
}

export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); }
  }));
  return out;
}
