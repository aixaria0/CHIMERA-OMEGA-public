import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';

// Separate implementation of the documented encoding, used only to check vectors.
function encode(v) {
  if (Array.isArray(v)) return `[${v.map(encode).join(',')}]`;
  if (v && typeof v === 'object') {
    const keys = Object.keys(v).sort();
    assert(keys.every(k => /^[\x00-\x7f]*$/.test(k)));
    return `{${keys.map(k => `${JSON.stringify(k)}:${encode(v[k])}`).join(',')}}`;
  }
  if (typeof v === 'number') assert(Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0));
  return JSON.stringify(v);
}
const hash = (domain, v) => crypto.createHash('sha256').update(`CHIMERA-OMEGA\0${domain}\0${encode(v)}`).digest('hex');

test('Node independently recomputes Rust fixture content addresses', () => {
  const envelope = JSON.parse(fs.readFileSync(new URL('../examples/v2/trace-match.json', import.meta.url)));
  envelope.claim.predicate.observed.sort();
  envelope.claim.predicate.negative_controls.sort();
  const claimDigest = hash('claim/v2', envelope.claim);
  for (const node of envelope.evidence) {
    node.body.parents.sort();
    assert.equal(node.body.claim_digest, claimDigest);
    assert.equal(node.digest, hash('evidence-node/v1', node.body));
  }
  envelope.evidence.sort((a,b) => a.body.id < b.body.id ? -1 : a.body.id > b.body.id ? 1 : 0);
  const expected = envelope.digest;
  delete envelope.digest;
  assert.equal(hash('envelope/v2', envelope), expected);
  assert.equal(fs.readFileSync(new URL('../examples/v2/trace-match.sha256', import.meta.url), 'utf8').trim(), expected);
});
