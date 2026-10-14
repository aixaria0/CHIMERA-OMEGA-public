# OMEGA v2: bounded offline evidence contract

Status: implemented Rust kernel, not formally verified. The initial policy is
`omega.trace-equality/v1`. It evaluates equality of supplied state-commitment
sequences. It does not execute the target or establish the truth of a prose claim.

## Input and policy

The public verification boundary is `verify(bytes, expected_digest)`. Every call
parses, validates, hashes and recomputes the result. Stored verdicts, confidence
scores, signatures and arbitrary extension fields are not accepted as input.
An unsupported field, schema, enum variant or policy causes rejection.

| Object | Required fields |
| --- | --- |
| Envelope | `schema`, `policy`, `claim`, `evidence`, `digest` |
| Claim | `schema`, `id`, `statement`, `epistemic_state`, `target`, `assumptions`, `limitations`, `predicate` |
| Target | `system`, `revision`, `configuration`, `environment` |
| Predicate | `kind`, `expected`, `observed`, `negative_controls` |
| Evidence node | `body`, `digest` |
| Evidence body | `schema`, `id`, `claim_digest`, `parents`, `evidence_class`, `producer`, `payload` |
| Producer | `id`, `kind` |

Schema identities are `chimera-evidence-envelope/v2`, `chimera-claim/v2`, and
`chimera-evidence-node/v1`. See `rust/src/model.rs` for the executable types and
`examples/v2/trace-match.json` for a complete package.

The claim's `statement` is descriptive. The only executable obligation is its
`trace_equality` predicate. `expected` identifies one trace; `observed` identifies
every observation; `negative_controls` identifies deterministic mutation recipes.
The three sets of roles must be disjoint. An empty observation set is insufficient
evidence, never a vacuous success. No claim-wide `verified` field exists.

`epistemic_state` is a producer declaration restricted to `PROPOSAL` or
`HYPOTHESIS`. The verifier returns a separate result; it never rewrites the claim
to `ESTABLISHED`. Changing the target revision, configuration, environment,
assumptions, limitations, predicate or statement changes its content identity.
Revision is an exact, nonempty opaque string, not a mutable reference resolved by
OMEGA. Configuration and environment are lowercase SHA-256 identity strings;
their underlying bytes are not acquired by this kernel.

## Evidence and provenance

Payloads are restricted to:

- `state_trace`: `states`, an ordered sequence of lowercase SHA-256 strings.
- `mutation_control`: `baseline`, `index`, `replacement`. The index selects a
  state in an observed trace. Replacement is another lowercase SHA-256 string.

State digests are opaque references. Comparing two references does not verify the
existence, correctness, or execution history of their raw states. The fixture
uses explicitly synthetic placeholder digest tokens.

Evidence classes are `SYNTHETIC` and `RECORDED`. Both are untrusted provenance
declarations. `RECORDED` does not mean live, authentic, independent or correct.
Mutation controls must be `SYNTHETIC`. Producer kinds are `HUMAN`, `PROGRAM`, and
`AI`; IDs are attributable labels only, without cryptographic authentication.

Every node binds the complete claim digest. Parent references identify prerequisite
nodes by ID. Duplicate IDs/references, absent parents, self-edges and cycles are
rejected. The deterministic topological order selects the lexicographically
smallest ready ID at each step. Control nodes must directly reference their
baseline as a parent. These checks establish graph consistency, not real-world
causality or observer independence.

Every node must have a predicate role. Unassigned nodes are rejected to prevent
an appended contradictory observation from being silently ignored. All declared
observations are compared; one contradiction takes precedence over agreement.
Omitted observations from outside the package remain unknowable. Node hashes
commit parent IDs; the envelope hash commits the full graph and all node hashes.
This is not a standalone Merkle ancestry-proof protocol.

## Encoding and hashes

Profile: `omega-json/v1` as specified here. This is a restricted encoding, not a
claim of general RFC 8785 conformance.

1. Accept at most 1 MiB of UTF-8 JSON, depth 32, and one complete JSON value.
2. Reject duplicate object keys, including differently escaped equivalents.
   Reject invalid Unicode, non-ASCII object keys and keys over 128 bytes.
3. Accept only unsigned integer JSON tokens in `0..9007199254740991`. Reject
   negative numbers, negative zero, decimal/exponent notation and non-finite
   values. Large domain numbers belong in adapter-defined strings or artifacts.
4. Preserve string values exactly: no Unicode normalization. Encode strings using
   JSON escapes for quotation marks, backslashes and control characters, with
   other Unicode emitted as UTF-8. No insignificant whitespace is emitted.
5. Sort object keys by ascending ASCII bytes. Preserve ordinary array order.
6. Before hashing, sort only declared set-like fields: evidence by node ID,
   parent IDs, observed IDs and control IDs. Duplicates remain errors. Trace,
   assumption and limitation arrays retain their order.
7. Serialize to canonical bytes, then use:

```text
SHA256(UTF8("CHIMERA-OMEGA") || 0x00 || UTF8(domain) || 0x00 || canonical_bytes)
```

| Domain | Hashed value |
| --- | --- |
| `claim/v2` | Complete normalized Claim |
| `evidence-node/v1` | Complete normalized node `body`, including claim binding |
| `envelope/v2` | Complete normalized Envelope with only its root `digest` removed |
| `report/v2` | Complete computed verification report |

Hashes are lowercase hexadecimal. Verify each node's claim binding and digest,
then the envelope digest, then the caller's expected digest. Self-consistent
rehashing cannot match a previously pinned package under the SHA-256 collision
resistance assumption. If the caller accepts a new pin, it accepts a different
artifact; hashing does not decide whether that acceptance is justified.

The caller must obtain its expected digest through its own trusted review process.
Copying it from an untrusted package defeats protection against replacement.
The checked-in fixture pin is a reproducibility anchor, not a production authority.

Resource limits also include 256 nodes/references per list, 2048 states per trace,
4096 bytes per string, 64 assumptions/limitations, and 128-byte ASCII identifiers
using letters, digits, `.`, `_`, `-`. At least one limitation is required.

## Verdict semantics

No total ordering of all epistemic states is asserted. In particular,
`NOT_APPLICABLE` is distinct from `UNKNOWN`; missing evidence cannot establish
non-applicability. The type represents both, but this policy never emits
`NOT_APPLICABLE` because it has no applicability checker.

| Dimension | Rule in this policy |
| --- | --- |
| Artifact conformance | `UNKNOWN` without observations; `CONTRADICTED` if any trace differs; otherwise `CONFIRMED` |
| Negative control | `FAIL` if any control is ineffective; `NOT_RUN` without successful coverage of every observation; otherwise `PASS` |
| Replay | `NOT_RUN`: no target execution replay is performed |
| Formal proof | `UNKNOWN`: no proof checker is invoked |
| Implementation binding | `UNKNOWN`: no implementation-to-model binding is checked |
| Runtime reproduction | `UNKNOWN`: no target execution is performed |
| Independent observation | `UNKNOWN`: neither identity authorization nor independence is established |
| Production reachability | `UNKNOWN`: no production path is exercised |
| Finality/externality | `UNKNOWN`: no consensus or external validity checker is invoked |

`CONFIRMED` means the named local predicate was evaluated successfully over the
pinned inputs. It never means universal correctness. `PASS` is confined to the
performed negative control. `NOT_RUN` indicates no completed check/coverage.
`UNKNOWN` indicates insufficient evidence for that dimension.

Aggregation is explicit, in precedence order:

1. Invalid encoding, structure, provenance, binding or integrity: **REJECTED**.
   Library returns an error; CLI emits a rejection without fabricated dimensions.
2. Any compared observation differs: **CONTRADICTED**, preserving each witness.
3. All observations match and each has a passing control, with no failing
   controls: **LOCALLY_SUPPORTED**, scoped to `PINNED_ARTIFACT_TRACE_EQUALITY_ONLY`.
4. Otherwise: **INCONCLUSIVE**. Missing or failed controls block local support.

`LOCALLY_SUPPORTED` does not aggregate unknown external dimensions into success.
It is explicitly local artifact support. A failed control does not itself refute
the claim; it prevents support. A valid counterexample does refute this predicate.

## Divergence, controls and replay

Comparison scans the state sequences in order. The first unequal index is
reported with the previous equal state commitment and both differing commitments.
An absent suffix produces `null` on the missing side. Index zero is an initial
state mismatch. Later indices locate the first differing trace boundary; they
do not establish the causal transition inside the target. This is a small local
witness, not a mathematically minimal counterexample.

Each control starts from a matching observed trace, replaces one commitment, and
reruns the same comparison function. A no-op replacement returns `FAIL`. A
baseline that already contradicts the predicate gives `NOT_RUN` for its control;
the original contradiction remains. Controls cover this comparison procedure;
the separate regression suite checks the rest of the verifier's rejection paths.

`omega replay` recomputes a report in the running process and compares it with a
supplied receipt using canonical JSON. It reports `REPRODUCED` or `DIVERGENT` with
scope `VERIFICATION_REPORT_ONLY_NOT_TARGET_EXECUTION`. It preserves the recomputed
layered report; it never promotes target replay or runtime reproduction. A stored
receipt has no authority. Process-isolated tests compare separate invocations.
Reports exclude wall-clock timestamps, random IDs and host-specific paths.

## Authoring, adapters and trust

`omega seal` is an authoring operation: it recomputes claim bindings, node hashes
and the envelope hash. It validates structure but intentionally allows a
contradicted predicate to be sealed and preserved. It does not sign or validate
truth. Digest placeholders in authoring input may be empty strings.

Adapters own state extraction and domain semantics. The kernel owns parsing,
binding, provenance, fixed-policy evaluation and reporting. There is no dynamic
plugin loader, target execution, database, networking or AI invocation. A new
predicate requires an explicit reviewed policy/implementation extension.

Trust assumptions: the reviewer trusts the verifier binary and its dependencies,
the source of the expected pin, and SHA-256 collision resistance. A pin establishes
an expected artifact identity, not an authorized signer. No signatures are
implemented; signed/unauthorized-identity fields are rejected as unsupported,
not described as cryptographically checked. Signature support would still not
establish truth. AI may author proposals, traces and controls, all under the same
untrusted input rules. Multiple labels or processes do not prove independence.
