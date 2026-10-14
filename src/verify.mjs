// Compatibility notice for v1 consumers. Evidence verification lives in Rust.
// V1 labels are producer assertions and cannot establish a verified claim.
export function verifyClaimEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) ||
      envelope.schema !== 'chimera-claim-envelope/v1') {
    return { status: 'FAIL', reasons: ['Unsupported legacy envelope; use the Rust v2 verifier.'] };
  }
  return {
    status: 'INCONCLUSIVE',
    scope: 'LEGACY_PRODUCER_ASSERTIONS_ONLY',
    claimId: envelope.claim?.id ?? null,
    declaredDimensions: envelope.dimensions ?? {},
    reasons: ['V1 does not bind evidence to verification obligations. No verification authority is inferred from its labels.'],
  };
}
