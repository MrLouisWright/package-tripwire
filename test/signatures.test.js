import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createSign, createPublicKey } from 'node:crypto';
import { verifyDistSignature, hasProvenance } from '../src/signatures.js';
import { analyze, parseAny } from '../src/index.js';
import { lock, mockRegistry, NOW } from './helpers.js';

function signedDist(name, version, integrity, keys) {
  const message = `${name}@${version}:${integrity}`;
  const sign = createSign('SHA256');
  sign.update(message);
  sign.end();
  const sig = sign.sign(keys.privateKey, 'base64');
  return {
    integrity,
    signatures: [{ keyid: keys.keyid, sig }],
  };
}

test('hasProvenance detects attestations', () => {
  assert.equal(hasProvenance({ dist: {} }), false);
  assert.equal(hasProvenance({ dist: { attestations: { url: 'https://registry.npmjs.org/-/npm/v1/attestations/pkg@1.0.0' } } }), true);
  assert.equal(hasProvenance({ dist: { attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } } }), true);
});

test('verifyDistSignature accepts a valid npm-style signature', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const der = publicKey.export({ type: 'spki', format: 'der' });
  const keyid = 'SHA256:test-key';
  const keys = [{ keyid, key: Buffer.from(der).toString('base64'), expires: null }];
  const dist = signedDist('left-pad', '1.1.0', 'sha512-left-pad-1.1.0', { privateKey, keyid });
  assert.equal(verifyDistSignature('left-pad', '1.1.0', dist, keys), 'valid');
  assert.equal(verifyDistSignature('left-pad', '1.1.0', { ...dist, signatures: [{ keyid, sig: 'AAAA' }] }, keys), 'invalid');
  assert.equal(verifyDistSignature('left-pad', '1.1.0', { integrity: dist.integrity }, keys), 'missing');
});

test('analyze flags invalid signatures, unsigned packages, and provenance loss', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const der = publicKey.export({ type: 'spki', format: 'der' });
  const keyid = 'SHA256:unit-test';
  const registryKeys = [{ keyid, key: Buffer.from(der).toString('base64'), expires: null }];
  const base = parseAny(lock([{ name: 'prov', version: '1.0.0' }]));
  const head = parseAny(lock([
    { name: 'prov', version: '2.0.0' },
    { name: 'unsigned', version: '1.0.0' },
    { name: 'badsig', version: '1.0.0' },
  ]));
  const reg = mockRegistry({
    prov: {
      time: { '1.0.0': new Date(NOW - 864e5).toISOString(), '2.0.0': new Date(NOW - 864e5).toISOString() },
      versions: {
        '1.0.0': { dist: { integrity: 'sha512-prov-1', attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } } },
        '2.0.0': { dist: { integrity: 'sha512-prov-2' } },
      },
    },
    unsigned: {
      time: { '1.0.0': new Date(NOW - 864e5).toISOString() },
      versions: { '1.0.0': { dist: { integrity: 'sha512-unsigned' } } },
    },
    badsig: {
      time: { '1.0.0': new Date(NOW - 864e5).toISOString() },
      versions: {
        '1.0.0': {
          dist: signedDist('badsig', '1.0.0', 'sha512-badsig', { privateKey: generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey, keyid }),
        },
      },
    },
  });
  reg.signingKeys = async () => registryKeys;
  const r = await analyze(base, head, { registry: reg, now: NOW });
  const rules = (pkg) => r.findings.filter((f) => f.package === pkg).map((f) => f.rule).sort();
  assert.ok(rules('prov').includes('provenance-lost'));
  assert.ok(rules('unsigned').includes('unsigned-package'));
  assert.ok(rules('badsig').includes('registry-signature-invalid'));
});
