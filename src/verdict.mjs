// Historical v1 label algebra only. Never use this as evidence verification.
// The Rust v2 verifier does not consume these labels or call this module.
export const Verdict = Object.freeze({
  PASS: 'PASS',
  FAIL: 'FAIL',
  INCONCLUSIVE: 'INCONCLUSIVE',
});

const hardFail = (x) => x === 'FAILED' || x === 'CONFLICTING' || x === 'DIVERGENT' || x === 'FAIL' || x === 'DISPROVEN';
const unknown = (x) => x === 'UNPROVEN' || x === 'PARTIAL' || x === 'UNBOUND' || x === 'INCONCLUSIVE' || x === 'NOT_RUN' || x === 'UNKNOWN' || x === 'NOT_ESTABLISHED';

export function deriveOverallClaimStatus(dimensions) {
  const values = Object.values(dimensions);
  if (values.some(hardFail)) return Verdict.FAIL;
  if (values.some(unknown)) return Verdict.INCONCLUSIVE;
  return Verdict.PASS;
}
