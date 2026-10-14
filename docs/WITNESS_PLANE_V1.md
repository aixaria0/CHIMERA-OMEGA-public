# Offline Ed25519 witness plane v1

Status: implemented bounded witness-identity and authorization boundary layered on the existing KV observer artifact path.

This capability establishes cryptographic attribution under an explicitly pinned authorization policy. It does **not** establish truth, live-target observation, physical independence, organizational independence, freshness, or finality.

## Purpose

Before this boundary, `omega-observer` could produce a deterministic observer receipt through a separate process and code path, but OMEGA deliberately left the observer unauthenticated.

Witness plane v1 adds two distinct artifacts:

```text
observer receipt
      |
      v
Ed25519 witness attestation

externally reviewed witness policy
      |
      v
explicit authorization
```

Verification joins them only after the underlying execution receipt, observer receipt, and evidence package have already passed their existing fail-closed binding checks.

## Governing rule

```text
SIGNATURE != TRUTH
KEY POSSESSION != AUTHORIZATION
AUTHORIZATION != INDEPENDENCE
```

A valid Ed25519 signature establishes that the holder of a specific private key signed the exact domain-separated attestation statement.

It does not establish that:

- the signed observation is true;
- the signer is honest;
- the signer controls a particular real-world identity;
- the signer ran on another machine;
- the signer is organizationally independent;
- the target was observed live;
- the evidence is fresh;
- the external system reached consensus or finality.

## Components

### `omega-witness`

A separate signer executable:

```sh
cargo run --locked --bin omega-witness -- \
  attest-kv-observer <observer-receipt.json> \
  --key <witness-secret.json> \
  --out <attestation.json>
```

The command emits `SIGNED_NOT_AUTHORIZED`.

The signer does not read an authorization policy and cannot grant itself authority.

### Witness secret

Schema:

```text
chimera-witness-secret/v1
```

Required scope:

```text
OFFLINE_ED25519_WITNESS_SIGNING_KEY_ONLY
```

The secret file contains:

- `witness_id`;
- one 32-byte Ed25519 signing seed encoded as 64 lowercase hexadecimal characters.

The signer derives the public key from the secret seed; callers cannot supply a mismatched public key.

The secret file is not content-addressed and must not be committed. OMEGA v1 does not provide hardened key storage, zeroization guarantees for all temporary process memory, HSM integration, key generation, rotation, recovery, or revocation services.

### Witness attestation

Schema:

```text
chimera-witness-attestation/v1
```

The signed statement binds:

- witness identifier;
- derived Ed25519 public key;
- role `KV_OBSERVER`;
- observer receipt digest;
- execution receipt digest;
- observation digest;
- exact schema and scope.

The signing message is OMEGA canonical JSON prefixed by the explicit domain:

```text
CHIMERA-OMEGA\0witness/ed25519-attestation/v1\0
```

The complete attestation, including the signature, is then content-addressed under:

```text
witness/attestation/v1
```

The signature is deterministic Ed25519. The attestation deliberately contains no timestamp or nonce. Replay of an immutable attestation is therefore possible and must not be interpreted as freshness.

## Authorization policy

Schema:

```text
chimera-witness-policy/v1
```

Required scope:

```text
EXPLICIT_OFFLINE_WITNESS_AUTHORIZATION_ONLY
```

Each authorization entry contains exactly:

```text
witness_id
public_key
role = KV_OBSERVER
```

Policy entries are canonically ordered. Duplicate witness identifiers and duplicate public keys are rejected. The current bound is 1..64 authorized witnesses.

Seal a draft policy with:

```sh
cargo run --locked --bin omega -- seal-witness-policy <draft-policy.json>
```

The resulting policy is content-addressed under:

```text
witness/policy/v1
```

Verification requires an independently supplied expected policy digest. A self-consistently modified and rehashed policy does not become authoritative unless the caller also explicitly selects that new policy digest.

There is no hidden trust store or database.

## End-to-end verification

```sh
cargo run --locked --bin omega -- \
  verify-kv-witness <package.json> \
  --expect <reviewed-package-digest> \
  --receipt <execution-receipt.json> \
  --observer <observer-receipt.json> \
  --expect-observer <reviewed-observer-digest> \
  --attestation <attestation.json> \
  --policy <witness-policy.json> \
  --expect-policy <reviewed-policy-digest>
```

The verifier first executes the existing package -> raw execution receipt -> observer receipt verification chain.

Only then does it:

1. strictly parse the witness policy and attestation;
2. recompute and check the policy content address;
3. require the caller-supplied policy pin;
4. recompute and check the attestation content address;
5. bind the attestation to the already verified observer artifact;
6. decode the Ed25519 public key and signature using canonical lowercase hex;
7. perform strict Ed25519 signature verification;
8. require an exact `(witness_id, public_key, KV_OBSERVER)` authorization entry in the pinned policy.

## Result semantics

A successful witness binding reports:

```text
status                  = CONFIRMED
signature_integrity     = CONFIRMED
policy_identity_binding = CONFIRMED
authorization           = CONFIRMED
independent_observation = UNKNOWN
```

The scope is:

```text
AUTHORIZED_ED25519_WITNESS_TO_PINNED_OBSERVER_ARTIFACT_ONLY
```

`policy_identity_binding = CONFIRMED` means only that the pinned policy maps the signed witness identifier to the verified public key for the required role. It is not proof of a legal, organizational, human, or hardware identity.

The core claim result remains separate. A valid, authorized witness may sign evidence belonging to a claim whose `claim_status` is `CONTRADICTED`; the witness binding can still be `CONFIRMED` because signature integrity and claim truth are different predicates.

## Adversarial controls

The witness regression suite requires fail-closed behavior for at least:

- a content-addressed attestation with an invalid Ed25519 signature;
- a cryptographically valid signature from a key absent from the pinned authorization policy;
- transplanting a valid signed attestation onto another observer artifact;
- modifying and fully rehashing a witness policy while retaining the previous caller policy pin;
- duplicate witness identifiers in policy;
- an authorized witness attesting evidence for a contradicted claim without promoting that claim to truth;
- an end-to-end separate `omega-witness` process followed by main-verifier authorization.

Existing observer and execution adversarial controls remain in force before witness verification is reached.

## Trust model

Witness plane v1 separates:

```text
content integrity
      !=
cryptographic key attribution
      !=
pinned-policy authorization
      !=
independent observation
      !=
truth
```

The policy is a caller-selected trust input, not discovered authority. Reusing an old policy pin intentionally reuses its old authorization decision; OMEGA v1 has no global revocation oracle.

## Explicit non-claims

Witness plane v1 does not establish:

- remote or physical host independence;
- operator independence;
- organizational independence;
- live-target observation;
- trusted execution or remote attestation;
- source-to-binary equivalence;
- private-key non-exfiltration;
- freshness;
- global key revocation;
- production reachability;
- consensus/finality;
- physical-world validity;
- truth of the underlying claim.

A future remote witness protocol may use this key/policy layer as an identity primitive, but it must establish its own replay, challenge, transport, independence, and live-observation boundaries rather than inheriting them from a signature.
