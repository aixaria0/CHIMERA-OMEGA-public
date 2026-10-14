# Deterministic KV adapter v1

Status: bounded local execution adapter for the existing OMEGA v2 evidence kernel.
It is not a production adapter, independent observer, formal model, or authority.

## Purpose

The v2 kernel evaluates supplied state commitments but deliberately does not
execute a target. `run-kv` adds one narrow execution boundary without changing the
core envelope, policy, verdict lattice, hash primitive, or trust model.

The adapter executes a deterministic in-process key/value state machine, preserves
its raw observed snapshots in a separate content-addressed receipt, converts both
supplied expected snapshots and executed observed snapshots into domain-separated
state commitments, and authors the existing `chimera-evidence-envelope/v2` shape.

The CLI result is intentionally `AUTHORED_NOT_VERIFIED`. Authoring evidence is not
verification authority. The resulting package still requires the normal external
pin review and `omega verify` path.

## Scenario contract

Schema: `chimera-kv-scenario/v1`.

```json
{
  "schema": "chimera-kv-scenario/v1",
  "id": "example",
  "initial": {"a": 1},
  "steps": [
    {"kind": "add", "key": "a", "delta": 2},
    {"kind": "put", "key": "b", "value": 5},
    {"kind": "delete", "key": "a"}
  ],
  "expected": [
    {"a": 1},
    {"a": 3},
    {"a": 3, "b": 5},
    {"b": 5}
  ]
}
```

Rules:

- input uses OMEGA's strict JSON parser and 1 MiB input bound;
- scenario IDs are bounded ASCII identifiers;
- keys are non-empty printable ASCII strings up to 128 bytes;
- state values are unsigned integers in `0..9007199254740991`;
- a state contains at most 256 keys;
- a scenario contains at most 256 transitions;
- `expected` contains the initial snapshot plus exactly one snapshot per step;
- `put` sets a key to the supplied value;
- `add` requires an existing key and uses checked arithmetic;
- `delete` requires an existing key;
- invalid transitions reject the scenario rather than inventing a state.

The expected snapshots are supplied evidence. The adapter does not infer that they
are correct. A mismatch with execution is intentionally preserved as a
`CONTRADICTED` package after core verification.

## Bound identities

The adapter binds execution into the existing claim target fields:

- `target.system = omega-kv-machine`;
- `target.revision` is a domain-separated digest of the exact
  `rust/src/adapter.rs` source text compiled into the binary;
- `target.configuration` is the domain-separated canonical digest of the complete
  scenario input;
- `target.environment` is the digest of the documented deterministic execution
  contract, not a claim about the host OS or hardware.

This source digest does **not** bind the compiler, linked dependencies, final
binary, operating system, CPU, or deployment environment. Those remain outside
this adapter's established boundary.

## Raw state and commitments

Every raw observed KV state is retained in a
`chimera-kv-execution-receipt/v1` receipt. Its state commitment is:

```text
SHA256(
  UTF8("CHIMERA-OMEGA") || 0x00 ||
  UTF8("adapter/kv-state/v1") || 0x00 ||
  canonical_json(raw_state)
)
```

The same state commitment procedure is applied to supplied expected snapshots.
The resulting commitments become the existing `state_trace` payloads. The core
envelope therefore stays protocol-agnostic and unchanged.

The receipt records:

- scenario identity and digest;
- adapter source digest;
- execution-contract digest;
- resulting package digest;
- every raw observed snapshot and its commitment;
- explicit limitations;
- a domain-separated receipt digest.

Receipt content addressing provides deterministic integrity checking only. It is
not a signature, authorization decision, independent observation, or truth claim.

## Evidence classes and control

The supplied expected trace is emitted as `SYNTHETIC`. The locally executed trace
is emitted as `RECORDED`, with the existing warning that this label is an untrusted
provenance declaration. A deterministic synthetic mutation control is authored
for the observed trace and directly depends on both `expected` and `observed`.

The adapter never writes stored verdict dimensions. The core verifier recomputes
them from the package.

For a matching adapter package, core verification may return
`LOCALLY_SUPPORTED` for `PINNED_ARTIFACT_TRACE_EQUALITY_ONLY`; the external
verification dimensions remain unchanged:

- formal proof: `UNKNOWN`;
- implementation binding: `UNKNOWN`;
- runtime reproduction: `UNKNOWN`;
- independent observation: `UNKNOWN`;
- replay: `NOT_RUN`;
- production reachability: `UNKNOWN`;
- finality/externality: `UNKNOWN`.

The adapter does perform a local execution, but v2 has no evidence dimension that
can safely promote that execution into runtime authority. Under-claiming is
intentional until a reviewed evidence model can represent and verify that boundary.

## CLI

```sh
cargo run --locked --bin omega -- run-kv examples/adapter/kv-match.json \
  --package /tmp/omega-kv-package.json \
  --receipt /tmp/omega-kv-receipt.json
```

The command writes two deterministic artifacts and prints an authoring summary.
The package digest printed by the authoring command is not automatically a trusted
pin. Review the package and obtain/record its expected digest through the caller's
trusted process, then verify it normally:

```sh
cargo run --locked --bin omega -- verify /tmp/omega-kv-package.json \
  --expect <reviewed-package-digest>
```

## Explicit non-claims

This adapter does not establish source-to-binary equivalence, formal correctness,
observer independence, production reachability, consensus/finality, physical
validity, or external truth. It performs no networking, database access, dynamic
plugin loading, AI inference, or hidden I/O.
