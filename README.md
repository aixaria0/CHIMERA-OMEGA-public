# CHIMERA OMEGA

**Proof-carrying evidence runtime — bounded Rust kernel, v0.2.0**

> No evidence, no claim. Verification is not a boolean.

OMEGA currently verifies a narrow, reproducible proposition: whether every supplied
observed state-commitment sequence equals a supplied expected sequence inside a
pinned evidence package. It validates claim/target binding and a provenance DAG,
recomputes the comparison, locates first divergence, and runs mutation controls.

A matching synthetic fixture supports this artifact-level proposition only.
Formal proof, implementation binding, runtime reproduction, independent observation,
production reachability and finality remain `UNKNOWN`. Target replay is `NOT_RUN`.
The system is not formally verified and does not establish external truth.

OMEGA can also import synthetic assurance packages and native verifier reports
from a pinned RCHAIN-COMPLIER revision. The importer checks package bytes,
caller-pinned report digest, task/claim/policy binding, and source revision, while
preserving Compiler `PASS` / `FAIL` / `BLOCKED` as an attributed external result.
It does not reverify Compiler signatures or promote that result to an OMEGA verdict.

The repository contains one bounded producer-side adapter: a deterministic in-process
KV state machine. It executes raw state transitions, preserves raw observed snapshots
in a content-addressed receipt, commits those snapshots into the existing v2 envelope,
and deliberately leaves the verifier's external dimensions unchanged. A separate
fail-closed receipt-binding path can prove that supplied raw KV snapshots correspond
to the observed commitments in an externally pinned package. Adapter execution and
receipt integrity are evidence boundaries, not automatic authority.

A second executable, `omega-observer`, provides a bounded observer-separation
boundary. It re-observes the supplied raw execution artifact through a separate
process and code path, producing its own content-addressed receipt. The main verifier
can bind that observer artifact to the execution receipt and pinned package. This is
artifact corroboration, not authenticated independent observation:
`independent_observation` remains `UNKNOWN`.

A third executable, `omega-witness`, can attach an offline Ed25519 attestation to an
observer receipt. The signer itself emits `SIGNED_NOT_AUTHORIZED`; authorization is
computed later by the main verifier from an explicitly supplied, content-addressed,
caller-pinned witness policy. A valid signature establishes key attribution for exact
bytes under that policy boundary. It does not establish truth or independence.

OMEGA also independently verifies signed operation/lineage bindings from
`aixaria0/aether-runtime`. `verify-aether-lineage` consumes a raw execution export
and a separately caller-pinned context selecting signer, source semantics and exact
certificate/journal checkpoint references. It recomputes Ed25519, operation results,
policy and graph/replay bindings; full journal-chain verification stays `UNKNOWN`
and the OMEGA core verdict stays `NOT_RUN`. The existing Aether Runtime OS importer
for the exact fields, recorded fixture command, acquisition steps and controls.

OMEGA also binds selected saved audit captures from the pinned staking-audit repository
to a reviewer-selected manifest and observation roles. `verify-audit-archive` preserves
raw bytes, reports unavailable files, and leaves authenticity, finding verdict and

## Run

Rust 1.90.0 is pinned in `rust-toolchain.toml`; dependencies are locked in
`Cargo.lock`. Direct dependencies are Serde, serde_json, SHA-2, and the exactly pinned
`ed25519-dalek` 2.2.0 with default features disabled. Building may download the
pinned toolchain/dependencies; the verifier, observer, and witness signer perform no
network I/O.

```sh
cargo test --locked
cargo run --locked --bin omega -- verify examples/v2/trace-match.json \
  --expect c2fde1c46452cbe0804b957f4ee080b0a2b14d3d1802ad3f77ef126bfee8c1c5
cargo run --locked --bin omega -- replay examples/v2/trace-match.json \
  --expect c2fde1c46452cbe0804b957f4ee080b0a2b14d3d1802ad3f77ef126bfee8c1c5 \
  --receipt examples/v2/trace-match.report.json
```

The literal pin above is for the checked-in synthetic fixture. For other packages,
obtain the expected digest through your trusted review process. Copying a digest
from an untrusted package does not protect against whole-package replacement.

`verify` prints a layered JSON report. `replay` recomputes the report and compares
it with the supplied receipt; `REPRODUCED` describes the verification report,
not a new execution of the target. A contradictory fixture is preserved in
`examples/v2/trace-divergent.json`, with its pin and report beside it.

| CLI exit | Meaning |
| --- | --- |
| 0 | Artifact predicate locally supported with passing controls, successful authoring, or a confirmed narrowly scoped receipt/observer/witness binding |
| 1 | Valid artifact contradicts the predicate, or report replay diverged |
| 2 | Input, policy, provenance, integrity, signature, authorization or caller pin rejected; also usage/I/O errors |
| 3 | Valid package has insufficient evidence or ineffective controls |

A reproduced report retains the exit status of its recomputed claim result.
Commands must be interpreted together with their explicit scope and dimensions.

## What is implemented

- Versioned claims, evidence nodes and fixed verification policy.
- Claim digests binding exact target identities, assumptions and obligations.
- Domain-separated SHA-256 addresses, expected-digest checks and bounded parsing.
- Duplicate/dangling/cyclic provenance rejection and deterministic traversal.
- All-observation trace comparison: one contradiction cannot be outvoted.
- Earliest differing index with a small witness; no mathematical-minimality claim.
- Synthetic mutation controls executed through the same comparison function.
- Deterministic report recomputation across separate CLI processes.
- A bounded deterministic KV adapter that converts real local execution snapshots
  into the existing evidence boundary without changing verdict authority.
- Fail-closed KV receipt verification binding raw states to the exact observed
  commitments in an externally pinned package, including resistance to a
  self-consistently rehashed but altered receipt.
- A separate `omega-observer` executable that recomputes raw KV snapshot commitments
  from the execution receipt and emits a deterministic content-addressed artifact.
- Fail-closed observer verification binding that artifact to the same execution
  receipt and pinned package while preserving `independent_observation = UNKNOWN`.
- Offline Ed25519 attestation of observer-artifact bindings through `omega-witness`.
- Explicit witness authorization through a separately content-addressed and
  caller-pinned policy; key possession alone grants no authority.
- Strict separation of signature integrity, policy-local identity binding,
  authorization, independent observation, and core claim status.
- Unknown dimensions remain unknown; stored assertions have no verdict authority.
- Offline Aether signed-operation/lineage verification under a separately pinned
  context, with recorded live fixtures, authenticated wrong-result controls and
  cross-repository CI artifacts. No new dependencies or core-verdict promotion.

The built-in `trace_equality` policy is the only implemented core predicate. State
hashes, producer IDs and evidence classes do not authenticate external events.
The witness verifier authenticates an Ed25519 key against a caller-pinned local
policy, but OMEGA still has no proof checker, authenticated remote observer, remote
attestation, production adapter, networking, or general target-execution engine.
The KV adapter is a narrow local execution producer, and `omega-observer` observes
its artifact rather than a live external target.

## Execute a bounded adapter scenario

The checked-in example exercises `put`, checked `add`, and `delete` transitions:

```sh
cargo run --locked --bin omega -- run-kv examples/adapter/kv-match.json \
  --package /tmp/omega-kv-package.json \
  --receipt /tmp/omega-kv-receipt.json
```

The command prints `AUTHORED_NOT_VERIFIED`, writes a sealed v2 package, and writes
an execution receipt containing the raw observed snapshots and their commitments.
The package binds the scenario digest, adapter source digest, and execution-contract
digest. None of these is a signature or independent witness.

Review the generated package and establish its expected digest through the caller's
trusted process before invoking `omega verify`. The raw receipt can then be checked
against that same pinned package:

```sh
cargo run --locked --bin omega -- verify-kv-receipt /tmp/omega-kv-package.json \
  --expect <reviewed-package-digest> \
  --receipt /tmp/omega-kv-receipt.json
```

This command recomputes every raw snapshot commitment, requires the sequence to
match the pinned package's single KV observed trace, checks package/scenario/source/
contract bindings, and recomputes the receipt digest. It reports
`KV_RAW_SNAPSHOT_TO_PINNED_PACKAGE_BINDING_ONLY`; it does not promote any core
verification dimension. A receipt may be correctly bound even when the package's
claim status is `CONTRADICTED`, because evidence integrity and claim truth are
separate predicates.

## Observe the execution artifact through a separate process

Produce an observer receipt from the raw execution receipt:

```sh
cargo run --locked --bin omega-observer -- \
  observe-kv /tmp/omega-kv-receipt.json \
  --out /tmp/omega-kv-observer.json
```

The observer prints `OBSERVED_NOT_AUTHORIZED`. It independently recomputes every
raw state commitment through its own module and executable, but it does not grant
itself verification authority.

After establishing the observer receipt digest through the caller's review path,
bind the full artifact chain:

```sh
cargo run --locked --bin omega -- \
  verify-kv-observer /tmp/omega-kv-package.json \
  --expect <reviewed-package-digest> \
  --receipt /tmp/omega-kv-receipt.json \
  --observer /tmp/omega-kv-observer.json \
  --expect-observer <reviewed-observer-receipt-digest>
```

A success reports `KV_OBSERVER_ARTIFACT_TO_PINNED_PACKAGE_BINDING_ONLY` and still
reports `independent_observation = UNKNOWN`. The implementation cannot authenticate
that the observer ran on a different host, under a different operator, or inside an
independent organization. It therefore does not claim those properties.

## Attribute and authorize an offline witness

`omega-witness` signs an already authored observer receipt. Its secret input is a
local file containing a witness identifier and a 32-byte Ed25519 seed encoded as
lowercase hex. Secret files are operational inputs and must not be committed.

```sh
cargo run --locked --bin omega-witness -- \
  attest-kv-observer /tmp/omega-kv-observer.json \
  --key /secure/path/witness-secret.json \
  --out /tmp/omega-witness-attestation.json
```

The signer reports `SIGNED_NOT_AUTHORIZED`. It does not read the authorization
policy and cannot authorize itself.

Prepare a witness-policy draft mapping an exact witness identifier and public key to
role `KV_OBSERVER`, then content-address it:

```sh
cargo run --locked --bin omega -- \
  seal-witness-policy witness-policy-draft.json > witness-policy.json
```

Establish the resulting policy digest through the caller's trusted review path. The
full witness check is then:

```sh
cargo run --locked --bin omega -- \
  verify-kv-witness /tmp/omega-kv-package.json \
  --expect <reviewed-package-digest> \
  --receipt /tmp/omega-kv-receipt.json \
  --observer /tmp/omega-kv-observer.json \
  --expect-observer <reviewed-observer-digest> \
  --attestation /tmp/omega-witness-attestation.json \
  --policy witness-policy.json \
  --expect-policy <reviewed-policy-digest>
```

A successful report keeps these predicates distinct:

```text
signature_integrity     = CONFIRMED
policy_identity_binding = CONFIRMED
authorization           = CONFIRMED
independent_observation = UNKNOWN
```

`policy_identity_binding` means the externally pinned policy maps that identifier to
that key for that role. It is not proof of a real-world human, machine, legal, or
organizational identity. The report also preserves the independently recomputed
`claim_status`; an authorized witness cannot turn a contradicted claim into truth.

The attestation contains no nonce or timestamp, so it establishes no freshness and
may be replayed as an immutable signed artifact. There is no global revocation oracle
or hidden trust store.

Even with a matching authorized witness, runtime reproduction on another machine,
independent observation, production reachability, and external/finality validity
remain unpromoted unless separate evidence establishes them.

See [KV adapter v1](docs/KV_ADAPTER_V1.md) for exact transition semantics, resource
bounds, digest domains, receipt fields, and explicit non-claims. See
[KV raw-receipt binding v1](docs/KV_RECEIPT_BINDING_V1.md) for the receipt verifier,
attack model, binding checks, and limitations. See
[KV artifact observer boundary v1](docs/OBSERVER_BOUNDARY_V1.md) for observer
separation. See [offline Ed25519 witness plane v1](docs/WITNESS_PLANE_V1.md) for
signature, authorization, replay and trust semantics.

## Author a package

Prepare the full v2 JSON shape shown in `examples/v2/trace-match.json`. During
authoring, `digest` and `claim_digest` values may be empty strings. Then:

```sh
cargo run --locked --bin omega -- seal draft.json > package.json
```

`seal` computes addresses and bindings and checks structure. It is not an
attestation. It deliberately preserves sealable counterexamples. Review the
artifact and establish its expected digest independently before verification.

## Specification and audit

- [v2 contract](docs/V2_SPEC.md): schemas, exact encoding, verdict rules, trust
  assumptions, provenance, controls, replay and adapter boundary.
  boundary for pinned Compiler artifacts and native reports.
  Ed25519 and exact raw operation/lineage binding for `aixaria0/aether-runtime`.
- [KV adapter v1](docs/KV_ADAPTER_V1.md): first bounded execution adapter and its
  raw-state/commitment boundary.
- [KV raw-receipt binding v1](docs/KV_RECEIPT_BINDING_V1.md): exact raw-state to
  pinned-package verification boundary and adversarial controls.
- [KV artifact observer boundary v1](docs/OBSERVER_BOUNDARY_V1.md): process/code-path
  observer separation, observer receipt semantics and explicit non-claims.
- [Offline Ed25519 witness plane v1](docs/WITNESS_PLANE_V1.md): signature domains,
  policy authorization, replay semantics and explicit trust limitations.
  measured checks, migration decisions and limitations.
- `rust/src/`: typed contract, encoding, verification, adapters, observer and witness
  binaries.
- `rust/tests/kernel.rs`: negative controls and process-level integration tests.
- `rust/tests/adapter.rs`: local execution, raw-receipt binding, transplant/rehash
  attacks, deterministic output and fail-closed adapter tests.
- `rust/tests/compiler.rs`: Compiler import binding and non-promotion tests.
- `rust/tests/observer.rs`: observer recomputation, forged receipt, transplant,
  full-rehash and separate-process adversarial tests.
- `rust/tests/witness.rs`: signature tampering, unauthorized key, attestation
  transplant, policy rehash/pin, duplicate authorization and truth-separation tests.
- `tests/vectors.test.mjs`: separate Node implementation checks content-address
  vectors. This is serialization cross-checking, not independent observation.

Run formatting, linting and the retained Node checks:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
npm test
```

## Migration from v1

The original v1 fixture and three label-algebra tests are retained. The JavaScript
verification entry point is now a compatibility notice: v1 assertions produce
`INCONCLUSIVE` (exit 3), never authoritative `PASS`. The old `canonicalJson` and
`sha256` exports were removed; v2 defines a new encoding/hash contract and does
not reuse v1 digests. `src/verdict.mjs` is historical label algebra only and is
not part of the Rust verifier. No automatic promotion from v1 to v2 is provided.

## Direction and lineage

The intended direction remains a protocol-agnostic proof-carrying evidence runtime.
The KV adapter demonstrates bounded execution acquisition; the artifact observer
separates producer/observer/verifier roles; and the witness plane adds explicit
key attribution and policy-local authorization without pretending that any of these
steps alone establish independent observation or truth. Future remote witnesses or
production adapters must establish their own challenge, replay, transport,
independence, live-observation, and external-validity boundaries.

RCHAIN-COMPLIER's offline review contract informed external pinning and the
separation of local package verification from live observation. The broader
methodological lineage includes the staking audit's falsification loop,
Sentinel's observer separation, rlsenti's provenance work, and Sovereign-Lattice's
separation of formal properties from implementation enforcement. These references
do not establish inherited proofs. Imported Compiler evidence remains explicitly
bounded by its adapter contract.

The offline `verify-aether-journal` consumer adds complete bounded journal-chain
and receipt-event verification under caller-pinned trust. See
the first-stage lineage report and leaves external anchoring, independent
observation and producer binary attestation UNKNOWN.

`verify-aether-historical-journal` adds offline exact-receipt authorization under
an externally pinned key/policy registry. It can independently verify a replay
child and parent under different reviewed keys, including retired keys, while
preserving the producer's current-key assessment. See
Registry freshness, authorization time and current live-key authority remain
UNKNOWN; public testnets and third-party operational targets are outside the
repository's execution boundary in [AGENTS.md](AGENTS.md).

four fresh native release builds across two CI jobs, retains exact source Git
objects and raw binaries, and compares saved bytes under explicit external pins.
Build execution remains attributed; independence, compiler correctness and the
source origin of older ONE capture binaries are not promoted by matching hashes.
