# KV raw-receipt binding v1

Status: implemented adapter-side integrity boundary for the existing OMEGA v2 kernel.
It does not change the core evidence schema, verification policy, trust model, hash
primitive, or layered verdict dimensions.

## Purpose

`run-kv` preserves raw observed KV snapshots in a separate
`chimera-kv-execution-receipt/v1` artifact while the core evidence envelope carries
only their state commitments. Before this boundary existed, the repository could
recompute the receipt digest in tests, but a caller had no fail-closed verification
path proving that the raw snapshots in a supplied receipt were the bytes committed
by an externally pinned evidence package.

`verify-kv-receipt` closes that narrow gap.

It verifies this chain:

```text
externally reviewed package pin
        |
        v
sealed v2 package
        |
        v
RECORDED observed state-trace commitments
        |
        v
receipt snapshot commitments
        |
        v
canonical raw KV snapshot states
```

A successful result is scoped to
`KV_RAW_SNAPSHOT_TO_PINNED_PACKAGE_BINDING_ONLY`.

## CLI

```sh
cargo run --locked --bin omega -- verify-kv-receipt <package.json> \
  --expect <reviewed-package-digest> \
  --receipt <receipt.json>
```

Success returns exit `0` and a
`chimera-kv-receipt-binding-report/v1` with status `CONFIRMED`.
Malformed, inconsistent, unbound, or tampered inputs are rejected through the
normal CLI rejection path with exit `2`.

The command first invokes the existing core verifier with the caller-supplied
package pin. It therefore does not accept a receipt as authority for package
identity.

## Checks

The binding verifier requires all of the following:

1. The package passes the existing encoding, schema, provenance, claim binding,
   node digest, envelope digest, and external-pin checks. A package may still
   have claim status `CONTRADICTED` or `INCONCLUSIVE`; receipt integrity is a
   separate question.
2. The receipt parses through OMEGA's strict bounded JSON parser and exact
   `chimera-kv-execution-receipt/v1` schema. Unknown receipt/snapshot fields are
   rejected.
3. Receipt scope and scenario identifier are valid and bounded.
4. `receipt.package_digest` equals the pinned package identity.
5. Scenario, adapter-source, and execution-contract identities agree with the
   package target configuration, revision, and environment.
6. The adapter-source digest also matches the exact `rust/src/adapter.rs` source
   text embedded in the running binary.
7. The execution-contract digest also matches the verifier's compiled KV
   transition contract.
8. The package contains exactly one KV observed trace produced under the bounded
   `omega-kv-adapter`/`PROGRAM` producer boundary.
9. Snapshot indexes are contiguous from zero, states satisfy the KV resource and
   numeric bounds, and each snapshot commitment is recomputed from its raw state.
10. The recomputed snapshot-commitment sequence equals the package's pinned
    observed trace exactly.
11. The receipt's own domain-separated digest is recomputed and checked.

The decisive anchor is the externally supplied package pin. Rehashing a modified
receipt cannot make changed raw snapshots match the already pinned observed trace.

## Adversarial controls

The regression suite preserves negative cases for:

- raw-state mutation with a stale snapshot/receipt digest;
- raw-state mutation followed by recomputing both the snapshot digest and the
  receipt digest;
- transplanting a valid receipt from a different package/scenario;
- CLI-level corrupted receipt rejection.

The second case is important: self-consistent content addressing is not treated as
external authority. A fully rehashed malicious receipt still fails because its
snapshot commitments no longer equal the observed commitments committed by the
externally pinned package.

## Result semantics

A successful binding report contains:

- `status = CONFIRMED`;
- the narrow binding scope;
- pinned package digest;
- recomputed receipt digest;
- observed evidence identifier;
- raw snapshot count;
- the independently recomputed core claim status;
- explicit limitations.

`claim_status` is reported rather than collapsed into the binding result. For
example, a correctly preserved execution receipt can be bound to a package whose
supplied expected trace is contradicted by the execution. In that case receipt
binding may be `CONFIRMED` while `claim_status` is `CONTRADICTED`.

This is intentional. Evidence integrity and claim truth are different predicates.

## Explicit non-claims

A confirmed raw-receipt binding does not establish:

- an authorized identity or digital signature;
- an independent observer;
- source-to-binary equivalence;
- compiler, dependency, OS, CPU, or hardware identity;
- runtime reproduction on another machine;
- production reachability;
- consensus or finality;
- physical-world validity;
- honesty of the expected snapshots;
- external truth.

No core verdict dimension is promoted by this adapter-side check. The existing
v2 report remains authoritative for the dimensions it actually computes.
