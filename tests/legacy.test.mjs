import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { verifyClaimEnvelope } from '../src/verify.mjs';

test('legacy assertions never become verified evidence', () => {
  const fixture = JSON.parse(fs.readFileSync(new URL('../examples/claim.pass.json', import.meta.url)));
  assert.equal(verifyClaimEnvelope(fixture).status, 'INCONCLUSIVE');
  fixture.evidence = [];
  assert.equal(verifyClaimEnvelope(fixture).status, 'INCONCLUSIVE');
  fixture.dimensions = {};
  assert.equal(verifyClaimEnvelope(fixture).status, 'INCONCLUSIVE');
});

test('legacy entry point rejects unsupported envelopes without throwing', () => {
  for (const input of [null, undefined, 42, [], {}, {schema:'chimera-evidence-envelope/v2'}]) {
    assert.equal(verifyClaimEnvelope(input).status, 'FAIL');
  }
});
