use crate::{
    encoding,
    model::{Overall, State},
    observer::{
        verify_kv_observer, KvObserverReceipt, KV_OBSERVER_ID, KV_OBSERVER_RECEIPT_SCHEMA,
        KV_OBSERVER_SCOPE,
    },
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

pub const WITNESS_SECRET_SCHEMA: &str = "chimera-witness-secret/v1";
pub const WITNESS_POLICY_SCHEMA: &str = "chimera-witness-policy/v1";
pub const WITNESS_ATTESTATION_SCHEMA: &str = "chimera-witness-attestation/v1";
pub const WITNESS_BINDING_SCHEMA: &str = "chimera-witness-binding-report/v1";
const WITNESS_SECRET_SCOPE: &str = "OFFLINE_ED25519_WITNESS_SIGNING_KEY_ONLY";
const WITNESS_POLICY_SCOPE: &str = "EXPLICIT_OFFLINE_WITNESS_AUTHORIZATION_ONLY";
const WITNESS_ATTESTATION_SCOPE: &str = "OFFLINE_ED25519_OBSERVER_ATTESTATION_ONLY";
const WITNESS_BINDING_SCOPE: &str = "AUTHORIZED_ED25519_WITNESS_TO_PINNED_OBSERVER_ARTIFACT_ONLY";
const WITNESS_ROLE: &str = "KV_OBSERVER";
const MAX_WITNESSES: usize = 64;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSecret {
    pub schema: String,
    pub scope: String,
    pub witness_id: String,
    pub secret_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WitnessAuthorization {
    pub witness_id: String,
    pub public_key: String,
    pub role: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessPolicy {
    pub schema: String,
    pub scope: String,
    pub authorized_witnesses: Vec<WitnessAuthorization>,
    pub limitations: Vec<String>,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAttestation {
    pub schema: String,
    pub scope: String,
    pub witness_id: String,
    pub public_key: String,
    pub role: String,
    pub observer_receipt_digest: String,
    pub execution_receipt_digest: String,
    pub observation_digest: String,
    pub signature: String,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct WitnessBindingReport {
    pub schema: String,
    pub status: State,
    pub scope: String,
    pub package_digest: String,
    pub observer_receipt_digest: String,
    pub witness_attestation_digest: String,
    pub witness_policy_digest: String,
    pub witness_id: String,
    pub public_key: String,
    pub signature_integrity: State,
    pub policy_identity_binding: State,
    pub authorization: State,
    pub independent_observation: State,
    pub claim_status: Overall,
    pub limitations: Vec<String>,
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err(format!(
            "{label} must be {} lowercase hex characters",
            N * 2
        ));
    }
    let bytes = value.as_bytes();
    let mut output = [0u8; N];
    for index in 0..N {
        let high = nibble(bytes[index * 2])
            .ok_or_else(|| format!("{label} must be lowercase hexadecimal"))?;
        let low = nibble(bytes[index * 2 + 1])
            .ok_or_else(|| format!("{label} must be lowercase hexadecimal"))?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn observer_receipt_digest(receipt: &KvObserverReceipt) -> Result<String, String> {
    let mut value = serde_json::to_value(receipt).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or("KV observer receipt must be an object")?
        .remove("digest");
    encoding::digest("observer/kv-receipt/v1", &value)
}

fn policy_digest(policy: &WitnessPolicy) -> Result<String, String> {
    let mut value = serde_json::to_value(policy).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or("witness policy must be an object")?
        .remove("digest");
    encoding::digest("witness/policy/v1", &value)
}

fn attestation_digest(attestation: &WitnessAttestation) -> Result<String, String> {
    let mut value = serde_json::to_value(attestation).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or("witness attestation must be an object")?
        .remove("digest");
    encoding::digest("witness/attestation/v1", &value)
}

fn signed_statement(attestation: &WitnessAttestation) -> Value {
    serde_json::json!({
        "schema": attestation.schema,
        "scope": attestation.scope,
        "witness_id": attestation.witness_id,
        "public_key": attestation.public_key,
        "role": attestation.role,
        "observer_receipt_digest": attestation.observer_receipt_digest,
        "execution_receipt_digest": attestation.execution_receipt_digest,
        "observation_digest": attestation.observation_digest
    })
}

fn signing_message(attestation: &WitnessAttestation) -> Result<Vec<u8>, String> {
    let canonical = encoding::canonical_json(&signed_statement(attestation))?;
    let mut message = b"CHIMERA-OMEGA\0witness/ed25519-attestation/v1\0".to_vec();
    message.extend_from_slice(canonical.as_bytes());
    Ok(message)
}

fn validate_policy(policy: &WitnessPolicy) -> Result<(), String> {
    if policy.schema != WITNESS_POLICY_SCHEMA || policy.scope != WITNESS_POLICY_SCOPE {
        return Err("unsupported witness policy boundary".into());
    }
    if policy.authorized_witnesses.is_empty() || policy.authorized_witnesses.len() > MAX_WITNESSES {
        return Err("witness policy requires 1..64 authorized witnesses".into());
    }

    let mut witness_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    let mut previous: Option<(&str, &str)> = None;
    for witness in &policy.authorized_witnesses {
        if !valid_identifier(&witness.witness_id) {
            return Err("invalid witness identifier in policy".into());
        }
        decode_hex::<32>(&witness.public_key, "witness public key")?;
        if witness.role != WITNESS_ROLE {
            return Err("unsupported witness authorization role".into());
        }
        if !witness_ids.insert(witness.witness_id.as_str()) {
            return Err("duplicate witness identifier in policy".into());
        }
        if !public_keys.insert(witness.public_key.as_str()) {
            return Err("duplicate witness public key in policy".into());
        }
        if let Some((previous_id, previous_key)) = previous {
            if (witness.witness_id.as_str(), witness.public_key.as_str())
                <= (previous_id, previous_key)
            {
                return Err("witness policy entries are not canonically ordered".into());
            }
        }
        previous = Some((&witness.witness_id, &witness.public_key));
    }

    if policy.limitations.len() > 32
        || policy
            .limitations
            .iter()
            .any(|item| item.is_empty() || item.len() > 4096)
    {
        return Err("invalid witness policy limitations".into());
    }
    Ok(())
}

pub fn seal_witness_policy(input: &[u8]) -> Result<WitnessPolicy, String> {
    let mut policy: WitnessPolicy =
        serde_json::from_value(encoding::parse(input)?).map_err(|error| error.to_string())?;
    policy.authorized_witnesses.sort_by(|left, right| {
        (&left.witness_id, &left.public_key).cmp(&(&right.witness_id, &right.public_key))
    });
    policy.digest.clear();
    validate_policy(&policy)?;
    policy.digest = policy_digest(&policy)?;
    Ok(policy)
}

pub fn attest_kv_observer(
    observer_receipt_input: &[u8],
    witness_secret_input: &[u8],
) -> Result<WitnessAttestation, String> {
    let observer: KvObserverReceipt =
        serde_json::from_value(encoding::parse(observer_receipt_input)?)
            .map_err(|error| error.to_string())?;
    if observer.schema != KV_OBSERVER_RECEIPT_SCHEMA
        || observer.scope != KV_OBSERVER_SCOPE
        || observer.observer_id != KV_OBSERVER_ID
    {
        return Err("witness requires a supported KV observer receipt".into());
    }
    if observer.digest != observer_receipt_digest(&observer)? {
        return Err("witness observer receipt digest mismatch".into());
    }
    if !encoding::is_digest(&observer.execution_receipt_digest)
        || !encoding::is_digest(&observer.observation_digest)
    {
        return Err("witness observer receipt contains malformed bindings".into());
    }

    let secret: WitnessSecret = serde_json::from_value(encoding::parse(witness_secret_input)?)
        .map_err(|error| error.to_string())?;
    if secret.schema != WITNESS_SECRET_SCHEMA || secret.scope != WITNESS_SECRET_SCOPE {
        return Err("unsupported witness secret boundary".into());
    }
    if !valid_identifier(&secret.witness_id) {
        return Err("invalid witness identifier".into());
    }
    let secret_bytes = decode_hex::<32>(&secret.secret_key, "witness secret key")?;
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let public_key = encode_hex(&signing_key.verifying_key().to_bytes());

    let mut attestation = WitnessAttestation {
        schema: WITNESS_ATTESTATION_SCHEMA.into(),
        scope: WITNESS_ATTESTATION_SCOPE.into(),
        witness_id: secret.witness_id,
        public_key,
        role: WITNESS_ROLE.into(),
        observer_receipt_digest: observer.digest,
        execution_receipt_digest: observer.execution_receipt_digest,
        observation_digest: observer.observation_digest,
        signature: String::new(),
        digest: String::new(),
    };
    let message = signing_message(&attestation)?;
    attestation.signature = encode_hex(&signing_key.sign(&message).to_bytes());
    attestation.digest = attestation_digest(&attestation)?;
    Ok(attestation)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_kv_witness(
    package_input: &[u8],
    expected_package_digest: &str,
    execution_receipt_input: &[u8],
    observer_receipt_input: &[u8],
    expected_observer_digest: &str,
    attestation_input: &[u8],
    policy_input: &[u8],
    expected_policy_digest: &str,
) -> Result<WitnessBindingReport, String> {
    let observer_binding = verify_kv_observer(
        package_input,
        expected_package_digest,
        execution_receipt_input,
        observer_receipt_input,
        expected_observer_digest,
    )?;

    if !encoding::is_digest(expected_policy_digest) {
        return Err("a caller-supplied witness policy digest pin is required".into());
    }
    let policy: WitnessPolicy = serde_json::from_value(encoding::parse(policy_input)?)
        .map_err(|error| error.to_string())?;
    validate_policy(&policy)?;
    if !encoding::is_digest(&policy.digest) || policy.digest != policy_digest(&policy)? {
        return Err("witness policy digest mismatch".into());
    }
    if policy.digest != expected_policy_digest {
        return Err("caller witness policy pin mismatch".into());
    }

    let attestation: WitnessAttestation =
        serde_json::from_value(encoding::parse(attestation_input)?)
            .map_err(|error| error.to_string())?;
    if attestation.schema != WITNESS_ATTESTATION_SCHEMA
        || attestation.scope != WITNESS_ATTESTATION_SCOPE
        || attestation.role != WITNESS_ROLE
    {
        return Err("unsupported witness attestation boundary".into());
    }
    if !valid_identifier(&attestation.witness_id) {
        return Err("invalid witness identifier in attestation".into());
    }
    if !encoding::is_digest(&attestation.observer_receipt_digest)
        || !encoding::is_digest(&attestation.execution_receipt_digest)
        || !encoding::is_digest(&attestation.observation_digest)
        || !encoding::is_digest(&attestation.digest)
    {
        return Err("malformed witness attestation digest".into());
    }
    if attestation.digest != attestation_digest(&attestation)? {
        return Err("witness attestation digest mismatch".into());
    }
    if attestation.observer_receipt_digest != observer_binding.observer_receipt_digest
        || attestation.execution_receipt_digest != observer_binding.execution_receipt_digest
        || attestation.observation_digest != observer_binding.observation_digest
    {
        return Err("witness attestation is bound to another observer artifact".into());
    }

    let public_key_bytes = decode_hex::<32>(&attestation.public_key, "witness public key")?;
    let signature_bytes = decode_hex::<64>(&attestation.signature, "witness signature")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| "invalid Ed25519 witness public key".to_string())?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&signing_message(&attestation)?, &signature)
        .map_err(|_| "invalid Ed25519 witness signature".to_string())?;

    let authorized = policy.authorized_witnesses.iter().any(|entry| {
        entry.witness_id == attestation.witness_id
            && entry.public_key == attestation.public_key
            && entry.role == WITNESS_ROLE
    });
    if !authorized {
        return Err("witness identity is not authorized by the pinned policy".into());
    }

    Ok(WitnessBindingReport {
        schema: WITNESS_BINDING_SCHEMA.into(),
        status: State::Confirmed,
        scope: WITNESS_BINDING_SCOPE.into(),
        package_digest: observer_binding.package_digest,
        observer_receipt_digest: observer_binding.observer_receipt_digest,
        witness_attestation_digest: attestation.digest,
        witness_policy_digest: policy.digest,
        witness_id: attestation.witness_id,
        public_key: attestation.public_key,
        signature_integrity: State::Confirmed,
        policy_identity_binding: State::Confirmed,
        authorization: State::Confirmed,
        independent_observation: State::Unknown,
        claim_status: observer_binding.claim_status,
        limitations: vec![
            "A valid Ed25519 signature establishes attributable integrity for the signed observer-artifact binding; it does not establish truth.".into(),
            "The witness identifier is bound to the public key only under the externally pinned policy; this is not proof of a real-world identity.".into(),
            "Authorization is derived only from the externally pinned witness policy; key possession alone does not grant authority.".into(),
            "independent_observation remains UNKNOWN because offline key attribution does not establish machine, operator, organizational, or live-target independence.".into(),
            "The attestation contains no freshness, revocation, or remote-attestation proof; deterministic replay of a valid signature is possible by design.".into(),
        ],
    })
}
