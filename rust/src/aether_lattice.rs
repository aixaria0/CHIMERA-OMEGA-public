//! Offline verification of signed aether-runtime operation/lineage bindings.
//! Producer assessment flags have no authority over this verifier's result.
use crate::{encoding, model::State};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const AETHER_LATTICE_REPOSITORY: &str = "aixaria0/aether-runtime";
pub const AETHER_LATTICE_REVISION: &str = "04d785f7beee5ff96d78e092a1d73b79987c9e0e";
pub const CONTEXT_DOMAIN: &str = "aether/lineage-context/v1";
pub const CERTIFICATE_DOMAIN: &str = "aether/lattice-certificate/v1";
const SIGNATURE_DOMAIN: &str = "aether.execution-receipt.v1";
const INVARIANTS: [&str; 9] = [
    "receipt_attestation",
    "trusted_signer",
    "record_binding",
    "operation_result",
    "current_policy",
    "verified_receipt_v2",
    "journal_integrity",
    "journal_receipt_binding",
    "replay_provenance",
];
const UNEVALUATED: [&str; 5] = [
    "perturbation_stability",
    "statistical_entropy",
    "generalized_model_fidelity",
    "external_journal_anchor",
    "executor_binary_attestation",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    schema: String,
    source_repository: String,
    source_revision: String,
    trusted_signer_fingerprint_sha256: String,
    certificate_digest: String,
    journal_head_sha256: String,
    journal_event_count: u64,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Attestation {
    algorithm: String,
    domain: String,
    public_key_hex: String,
    key_fingerprint_sha256: String,
    signature_hex: String,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Receipt {
    receipt_version: u32,
    receipt_sha256: String,
    task_id: String,
    permit_id: String,
    parent_task_id: Option<String>,
    operation: String,
    input_sha256: String,
    output_sha256: String,
    policy_sha256: String,
    policy_revision: u32,
    capabilities: u64,
    capability_names: Vec<String>,
    executor_id: String,
    executor_identity_sha256: String,
    deadline_ms: u64,
    elapsed_ms: u64,
    verified: bool,
    attestation: Attestation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Execution {
    task_id: String,
    parent_task_id: Option<String>,
    operation: String,
    payload: String,
    output: String,
    receipt: Receipt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    schema: String,
    certificate: Value,
    execution: Execution,
    parent: Option<Execution>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    id: String,
    kind: String,
    sha256: String,
    parent: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Transformation {
    id: String,
    operation: String,
    input: String,
    output: String,
    evidence_ref: String,
    replay_of: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProducerReceiptVerification {
    digest_matches: bool,
    signature_present: bool,
    algorithm_supported: bool,
    domain_matches: bool,
    fingerprint_matches: bool,
    signature_valid: bool,
    valid: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalCheckpoint {
    valid: bool,
    event_count: u64,
    head_hash: Option<String>,
    first_invalid_sequence: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    source: String,
    receipt: Receipt,
    receipt_verification: ProducerReceiptVerification,
    journal: JournalCheckpoint,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invariant {
    name: String,
    passed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assessment {
    status: String,
    scope: String,
    trusted_signer_fingerprint_sha256: String,
    failed_invariants: Vec<String>,
    not_evaluated: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Certificate {
    schema: String,
    artifacts: [Artifact; 2],
    transformation: Transformation,
    evidence: Evidence,
    invariants: [Invariant; 9],
    assessment: Assessment,
}

#[derive(Serialize)]
pub struct AetherLineageBinding {
    pub schema: &'static str,
    pub status: State,
    pub scope: &'static str,
    pub context_digest: String,
    pub certificate_digest: String,
    pub evidence_digest: String,
    pub source_repository: &'static str,
    pub supported_revision: &'static str,
    pub task_id: String,
    pub receipt_sha256: String,
    pub trusted_signer_fingerprint_sha256: String,
    pub signature_integrity: State,
    pub raw_operation_binding: State,
    pub current_policy_binding: State,
    pub lineage_reference_binding: State,
    pub direct_replay_binding: State,
    pub journal_checkpoint_binding: State,
    pub journal_chain_integrity: State,
    pub independent_observation: State,
    pub producer_binary_attestation: State,
    pub omega_core_verdict: State,
    pub runtime_reproduction: State,
    pub producer_assessment: String,
    pub producer_failed_invariants: Vec<String>,
    pub producer_journal_valid: bool,
    pub not_evaluated: Vec<&'static str>,
    pub limitations: Vec<&'static str>,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2 || !text.is_ascii() {
        return Err("invalid Ed25519 hex length".into());
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err("Ed25519 fields require lowercase hexadecimal".to_string()),
    };
    let mut bytes = [0; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    Ok(bytes)
}

pub(crate) fn is_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

// Aether signs a plain SHA-256 of ordered ReceiptDigest struct serialization.
// OMEGA canonical JSON has different ordering/domain semantics and cannot replace it.
fn receipt_digest(receipt: &Receipt) -> Result<String, String> {
    let value = serde_json::to_value(receipt).map_err(|e| e.to_string())?;
    let fields = [
        "receipt_version",
        "task_id",
        "permit_id",
        "parent_task_id",
        "operation",
        "input_sha256",
        "output_sha256",
        "policy_sha256",
        "policy_revision",
        "capabilities",
        "capability_names",
        "executor_id",
        "executor_identity_sha256",
        "deadline_ms",
        "elapsed_ms",
        "verified",
    ];
    let pairs = fields
        .iter()
        .map(|key| {
            Ok(format!(
                "{}:{}",
                serde_json::to_string(key).map_err(|e| e.to_string())?,
                serde_json::to_string(&value[*key]).map_err(|e| e.to_string())?
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(sha256(format!("{{{}}}", pairs.join(",")).as_bytes()))
}

fn signature_message(receipt_digest: &str) -> Vec<u8> {
    let mut message = (SIGNATURE_DOMAIN.len() as u64).to_be_bytes().to_vec();
    message.extend_from_slice(SIGNATURE_DOMAIN.as_bytes());
    message.extend_from_slice(receipt_digest.as_bytes());
    message
}

fn verify_receipt(receipt: &Receipt, trusted: &str) -> Result<(), String> {
    if receipt.receipt_version != 2 || !receipt.verified {
        return Err("requires a verified Aether v2 receipt".into());
    }
    if !encoding::is_digest(&receipt.receipt_sha256)
        || receipt_digest(receipt)? != receipt.receipt_sha256
    {
        return Err("Aether receipt digest mismatch".into());
    }
    let attestation = &receipt.attestation;
    if attestation.algorithm != "ed25519" || attestation.domain != SIGNATURE_DOMAIN {
        return Err("unsupported Aether signature algorithm/domain".into());
    }
    let public_key = decode_hex::<32>(&attestation.public_key_hex)?;
    if sha256(&public_key) != attestation.key_fingerprint_sha256 {
        return Err("Aether signer fingerprint mismatch".into());
    }
    let key = VerifyingKey::from_bytes(&public_key).map_err(|e| e.to_string())?;
    let signature = Signature::from_bytes(&decode_hex::<64>(&attestation.signature_hex)?);
    key.verify_strict(&signature_message(&receipt.receipt_sha256), &signature)
        .map_err(|_| "Aether receipt signature rejected".to_string())?;
    if attestation.key_fingerprint_sha256 != trusted {
        return Err("Aether signer is not trusted by the pinned context".into());
    }
    Ok(())
}

fn verify_execution(execution: &Execution, trusted: &str) -> Result<(), String> {
    let receipt = &execution.receipt;
    verify_receipt(receipt, trusted)?;
    if !is_uuid(&execution.task_id)
        || !is_uuid(&receipt.permit_id)
        || execution.task_id != receipt.task_id
        || execution.parent_task_id != receipt.parent_task_id
        || execution.operation != receipt.operation
        || sha256(execution.payload.as_bytes()) != receipt.input_sha256
        || sha256(execution.output.as_bytes()) != receipt.output_sha256
    {
        return Err("raw Aether execution/receipt binding mismatch".into());
    }
    let expected = match receipt.operation.as_str() {
        "echo" => execution.payload.clone(),
        "uppercase" if execution.payload.is_ascii() => execution.payload.to_ascii_uppercase(),
        "sha256" => sha256(execution.payload.as_bytes()),
        _ => return Err("unsupported Aether operation/input semantics".into()),
    };
    if execution.output != expected {
        return Err("Aether operation result mismatch".into());
    }
    if receipt.policy_revision != 1
        || receipt.capabilities != 1
        || receipt.capability_names != ["compute"]
        || !matches!(
            receipt.executor_id.as_str(),
            "cpp-grpc-v1" | "rust-builtin-v1"
        )
        || !(1..=10_000).contains(&receipt.deadline_ms)
    {
        return Err("Aether compute policy rejected".into());
    }
    let descriptor = policy_descriptor(
        &receipt.operation,
        &receipt.executor_id,
        receipt.deadline_ms,
    )?;
    if sha256(descriptor.as_bytes()) != receipt.policy_sha256
        || sha256(receipt.executor_id.as_bytes()) != receipt.executor_identity_sha256
    {
        return Err("Aether policy/executor descriptor digest mismatch".into());
    }
    Ok(())
}

fn check_projection(certificate: &Certificate, execution: &Execution) -> Result<(), String> {
    let failed: Vec<_> = certificate
        .invariants
        .iter()
        .zip(INVARIANTS)
        .map(|(item, name)| {
            if item.name != name {
                return Err("unsupported Lattice invariant contract".to_string());
            }
            Ok((!item.passed).then(|| item.name.clone()))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    if certificate.schema != "lattice-ontology/v1"
        || certificate.assessment.scope != "allowlisted_execution_lineage"
        || certificate.assessment.failed_invariants != failed
        || certificate.assessment.status
            != if failed.is_empty() {
                "accepted"
            } else {
                "rejected"
            }
        || certificate.assessment.not_evaluated != UNEVALUATED
    {
        return Err("inconsistent or unsupported Lattice producer assessment".into());
    }
    let task = &execution.task_id;
    let input_id = format!("aether:artifact:{task}:input");
    let output_id = format!("aether:artifact:{task}:output");
    let [input, output] = &certificate.artifacts;
    let transform = &certificate.transformation;
    if input.id != input_id
        || output.id != output_id
        || input.kind != "execution_input"
        || output.kind != "execution_output"
        || input.parent.is_some()
        || output.parent.as_deref() != Some(&input_id)
        || input.sha256 != execution.receipt.input_sha256
        || output.sha256 != execution.receipt.output_sha256
        || transform.id != format!("aether:transformation:{task}")
        || transform.operation != execution.operation
        || transform.input != input_id
        || transform.output != output_id
        || transform.evidence_ref != execution.receipt.receipt_sha256
        || transform.replay_of
            != execution
                .parent_task_id
                .as_ref()
                .map(|id| format!("aether:transformation:{id}"))
        || certificate.evidence.source != format!("/evidence/{task}")
        || certificate.evidence.receipt != execution.receipt
    {
        return Err("Lattice artifact/transformation/receipt reference mismatch".into());
    }
    Ok(())
}

pub(crate) fn policy_descriptor(
    operation: &str,
    executor: &str,
    deadline_ms: u64,
) -> Result<String, String> {
    if !matches!(operation, "echo" | "uppercase" | "sha256")
        || !matches!(executor, "cpp-grpc-v1" | "rust-builtin-v1")
        || !(1..=10_000).contains(&deadline_ms)
    {
        return Err("unsupported Aether policy descriptor".into());
    }
    Ok(format!("aether-policy-v1|operation={operation}|capabilities=1|max-input=65536|max-output=65536|deadline-ms={deadline_ms}|executor={executor}"))
}

pub(crate) struct SelectedLineage {
    pub certificate_digest: String,
    pub journal_head_sha256: String,
    pub journal_event_count: u64,
    pub execution_signer: String,
    pub parent_signer: Option<String>,
    pub require_producer_signer: bool,
}

pub(crate) struct VerifiedLineage {
    pub evidence_digest: String,
    pub certificate_digest: String,
    pub task_id: String,
    pub receipt_sha256: String,
    pub direct_replay_binding: State,
    pub producer_assessment: String,
    pub producer_failed_invariants: Vec<String>,
    pub producer_journal_valid: bool,
    pub producer_selected_signer: String,
}

/// Shared cryptographic, raw-operation and projection checks. Selection authority
/// belongs to the caller's separately pinned contract, never producer flags.
pub(crate) fn verify_selected_lineage(
    evidence_bytes: &[u8],
    selected: &SelectedLineage,
) -> Result<VerifiedLineage, String> {
    let evidence_value = encoding::parse(evidence_bytes)?;
    let evidence_digest = encoding::digest("aether/lineage-evidence/v1", &evidence_value)?;
    let bundle: Bundle = serde_json::from_value(evidence_value).map_err(|e| e.to_string())?;
    if bundle.schema != "chimera-aether-lineage-evidence/v1" {
        return Err("unsupported Aether evidence export".into());
    }
    let certificate_digest = encoding::digest(CERTIFICATE_DOMAIN, &bundle.certificate)?;
    if certificate_digest != selected.certificate_digest {
        return Err("caller-pinned Lattice certificate digest mismatch".into());
    }
    let certificate: Certificate =
        serde_json::from_value(bundle.certificate).map_err(|e| e.to_string())?;
    verify_execution(&bundle.execution, &selected.execution_signer)?;
    check_projection(&certificate, &bundle.execution)?;
    if !encoding::is_digest(&certificate.assessment.trusted_signer_fingerprint_sha256)
        || (selected.require_producer_signer
            && certificate.assessment.trusted_signer_fingerprint_sha256
                != selected.execution_signer)
        || certificate.evidence.journal.head_hash.as_deref() != Some(&selected.journal_head_sha256)
        || certificate.evidence.journal.event_count != selected.journal_event_count
    {
        return Err("Lattice signer/journal checkpoint reference mismatch".into());
    }
    let direct_replay_binding = match (
        &bundle.execution.parent_task_id,
        &bundle.parent,
        &selected.parent_signer,
    ) {
        (None, None, None) => State::NotApplicable,
        (Some(id), Some(parent), Some(parent_signer)) => {
            verify_execution(parent, parent_signer)?;
            if *id != parent.task_id
                || parent.task_id == bundle.execution.task_id
                || parent.operation != bundle.execution.operation
                || parent.payload != bundle.execution.payload
            {
                return Err("Aether direct replay parent binding mismatch".into());
            }
            State::Confirmed
        }
        _ => return Err("Aether replay requires exactly its authenticated direct parent".into()),
    };
    Ok(VerifiedLineage {
        evidence_digest,
        certificate_digest,
        task_id: bundle.execution.task_id,
        receipt_sha256: bundle.execution.receipt.receipt_sha256,
        direct_replay_binding,
        producer_assessment: certificate.assessment.status,
        producer_failed_invariants: certificate.assessment.failed_invariants,
        producer_journal_valid: certificate.evidence.journal.valid,
        producer_selected_signer: certificate.assessment.trusted_signer_fingerprint_sha256,
    })
}

/// A caller pin selects trust and exact certificate/checkpoint references.
/// A successful binding is scoped; no producer flags or OMEGA core verdicts are promoted.
pub fn verify_aether_lineage(
    evidence_bytes: &[u8],
    context_bytes: &[u8],
    expected_context_digest: &str,
) -> Result<AetherLineageBinding, String> {
    if !encoding::is_digest(expected_context_digest) {
        return Err("invalid external Aether context pin".into());
    }
    let context_value = encoding::parse(context_bytes)?;
    let context_digest = encoding::digest(CONTEXT_DOMAIN, &context_value)?;
    if context_digest != expected_context_digest {
        return Err("caller-pinned Aether context digest mismatch".into());
    }
    let context: Context = serde_json::from_value(context_value).map_err(|e| e.to_string())?;
    if context.schema != "chimera-aether-lineage-context/v1"
        || context.source_repository != AETHER_LATTICE_REPOSITORY
        || context.source_revision != AETHER_LATTICE_REVISION
        || !encoding::is_digest(&context.trusted_signer_fingerprint_sha256)
        || !encoding::is_digest(&context.certificate_digest)
        || !encoding::is_digest(&context.journal_head_sha256)
        || context.journal_event_count == 0
    {
        return Err("unsupported Aether verifier context".into());
    }
    let evidence_value = encoding::parse(evidence_bytes)?;
    let parent_signer = if evidence_value["parent"].is_null() {
        None
    } else {
        Some(context.trusted_signer_fingerprint_sha256.clone())
    };
    let checked = verify_selected_lineage(
        evidence_bytes,
        &SelectedLineage {
            certificate_digest: context.certificate_digest.clone(),
            journal_head_sha256: context.journal_head_sha256.clone(),
            journal_event_count: context.journal_event_count,
            execution_signer: context.trusted_signer_fingerprint_sha256.clone(),
            parent_signer,
            require_producer_signer: true,
        },
    )?;
    Ok(AetherLineageBinding {
        schema: "chimera-aether-lineage-binding/v1", status: State::Confirmed,
        scope: "SIGNED_AETHER_OPERATION_AND_PINNED_LINEAGE_BINDING_ONLY",
        context_digest, certificate_digest: checked.certificate_digest, evidence_digest: checked.evidence_digest,
        source_repository: AETHER_LATTICE_REPOSITORY, supported_revision: AETHER_LATTICE_REVISION,
        task_id: checked.task_id, receipt_sha256: checked.receipt_sha256,
        trusted_signer_fingerprint_sha256: context.trusted_signer_fingerprint_sha256,
        signature_integrity: State::Confirmed, raw_operation_binding: State::Confirmed,
        current_policy_binding: State::Confirmed, lineage_reference_binding: State::Confirmed,
        direct_replay_binding: checked.direct_replay_binding, journal_checkpoint_binding: State::Confirmed,
        journal_chain_integrity: State::Unknown, independent_observation: State::Unknown,
        producer_binary_attestation: State::Unknown, omega_core_verdict: State::NotRun,
        runtime_reproduction: State::NotRun,
        producer_assessment: checked.producer_assessment,
        producer_failed_invariants: checked.producer_failed_invariants,
        producer_journal_valid: checked.producer_journal_valid,
        not_evaluated: UNEVALUATED.to_vec(),
        limitations: vec![
            "The external context pin must come from the verifier's trusted review process; producer-provided pins do not select authority.",
            "The certificate is unsigned. OMEGA independently checks its exact references, the embedded signed receipt and raw operation bytes.",
            "The supplied journal head/count are bound to the selected checkpoint; full journal events and receipt-event binding are not verified.",
            "Replay binds only the authenticated direct parent and original input; ancestry beyond that parent is not evaluated.",
            "Source revision pins supported wire/operation semantics, not the producer binary or its execution environment.",
            "No target executor is rerun; elapsed time, freshness, input origin, key custody, independent observation and external truth are not established.",
            "OMEGA's bounded JSON profile limits strings to 4096 UTF-8 bytes, narrower than Aether's 64 KiB admission bounds.",
            "No OMEGA core verdict dimension is promoted by this binding.",
        ],
    })
}
