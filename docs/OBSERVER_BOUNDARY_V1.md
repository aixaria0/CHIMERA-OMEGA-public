# KV artifact observer boundary v1

Status: implemented local process-separation boundary for the existing OMEGA v2 kernel and deterministic KV adapter.

This boundary deliberately does **not** claim authenticated independent observation.

## Purpose

The KV adapter already executes a bounded state machine and preserves raw snapshots in a content-addressed execution receipt. The core verifier can bind that receipt to an externally pinned evidence package.

That still leaves producer and observer collapsed into one implementation path.

`omega-observer` introduces a separate executable and a separate observation code path. It consumes only the raw KV execution receipt, independently recomputes every snapshot commitment, and emits a content-addressed observer receipt.

The main `omega` verifier can then bind that observer receipt back to the same raw execution receipt and externally pinned package.

The resulting chain is:

```text
executor / producer
        |
        v
raw KV execution receipt
        |
        v
separate omega-observer process
        |
        v
observer receipt
        |
        v
OMEGA verifier
        |
        +--> externally pinned evidence package
```

This is process and code-path separation. It is not yet authenticated machine, operator, organizational, or key independence.

## Observer command

```sh
cargo run --locked --bin omega-observer -- \
  observe-kv <execution-receipt.json> \
  --out <observer-receipt.json>
```

Success writes `chimera-kv-observer-receipt/v1` and prints an authoring result with:

```text
status = OBSERVED_NOT_AUTHORIZED
scope  = LOCAL_KV_ARTIFACT_OBSERVER_ONLY
```

The wording is intentional. The observer produces evidence; it does not grant itself verdict authority.

## Verification command

```sh
cargo run --locked --bin omega -- \
  verify-kv-observer <package.json> \
  --expect <reviewed-package-digest> \
  --receipt <execution-receipt.json> \
  --observer <observer-receipt.json> \
  --expect-observer <reviewed-observer-receipt-digest>
```

The verifier first applies the existing raw-receipt-to-package binding. It then requires the observer receipt to match a fresh deterministic recomputation from the supplied raw execution receipt.

A successful result has:

```text
status = CONFIRMED
scope  = KV_OBSERVER_ARTIFACT_TO_PINNED_PACKAGE_BINDING_ONLY
independent_observation = UNKNOWN
```

The explicit `UNKNOWN` is part of the contract, not an implementation gap to hide.

## Observer receipt contents

The receipt binds:

- exact execution-receipt digest;
- observer source-text digest;
- observer contract digest;
- contiguous snapshot count;
- independently recomputed snapshot commitments;
- an observation digest over the input receipt identity and commitment sequence;
- explicit limitations;
- a domain-separated observer-receipt digest.

The observer source digest binds the checked source text embedded in the binary. It does not establish source-to-binary equivalence or host identity.

## Fail-closed checks

The observer rejects:

- unsupported execution-receipt schema or scope;
- malformed execution-receipt digest;
- execution receipt whose content no longer matches its digest;
- missing or excessive snapshots;
- non-contiguous snapshot indexes;
- invalid KV key/value bounds;
- malformed snapshot digests;
- raw snapshots that do not recompute to their recorded commitments.

The main verifier additionally rejects:

- missing or malformed caller observer pin;
- observer receipt with the wrong schema, scope, or observer identifier;
- malformed observer digests;
- caller observer-pin mismatch;
- observer receipt bound to another execution receipt;
- observer receipt that differs from deterministic recomputation;
- any execution receipt that no longer binds to the externally pinned package.

## Adversarial controls

The regression suite includes:

1. stale raw-state mutation;
2. fully rehashed execution-receipt mutation;
3. fully rehashed forged observer receipt, including a caller pin for the forged digest;
4. observer-receipt transplant from another execution;
5. two separate observer-process runs required to emit byte-identical receipts;
6. end-to-end verifier confirmation that still leaves `independent_observation = UNKNOWN`.

The forged-observer case is important. A caller pin is necessary for artifact identity, but a self-consistent forged artifact does not become authoritative merely because its hash is internally valid. The verifier recomputes the observation from the raw receipt and rejects disagreement.

## Trust model

This boundary separates three roles:

```text
producer  -> creates execution artifact
observer  -> recomputes an observation from that artifact
verifier  -> checks bindings and policy
```

It does **not** prove that the roles were executed on different machines, by different operators, or by independent organizations.

No digital signature is introduced. No observer key is authorized. No remote attestation is performed. No network service is contacted.

Therefore:

```text
process/code-path corroboration: implemented
artifact binding:               confirmable
authenticated observer identity: not established
organizational independence:     not established
live-target observation:         not established
independent_observation verdict: UNKNOWN
```

## Explicit non-claims

A confirmed observer binding does not establish:

- live observation of the target system;
- authenticated observer identity;
- source-to-binary equivalence;
- host or hardware identity;
- execution on a separate physical machine;
- organizational independence;
- production reachability;
- distributed consensus or finality;
- physical-world validity;
- truth of expected snapshots;
- external truth.

The boundary exists to make a future authenticated or remote observer integration possible without first pretending that local process separation already provides those properties.
