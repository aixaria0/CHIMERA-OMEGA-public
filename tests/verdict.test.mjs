import test from 'node:test';
import assert from 'node:assert/strict';
import { deriveOverallClaimStatus } from '../src/verdict.mjs';

const complete = {
  formalProof: 'PROVEN',
  implementationBinding: 'BOUND',
  runtimeReproduction: 'CONFIRMED',
  independentObservation: 'CONFIRMED',
  replay: 'CONFIRMED',
  negativeControl: 'PASS',
  productionReachability: 'CONFIRMED',
  finalityExternality: 'ESTABLISHED',
};

test('all established dimensions derive PASS', () => {
  assert.equal(deriveOverallClaimStatus(complete), 'PASS');
});

test('unknown production reachability prevents overclaiming', () => {
  assert.equal(deriveOverallClaimStatus({ ...complete, productionReachability: 'UNKNOWN' }), 'INCONCLUSIVE');
});

test('conflicting independent observation is a hard failure', () => {
  assert.equal(deriveOverallClaimStatus({ ...complete, independentObservation: 'CONFLICTING' }), 'FAIL');
});
