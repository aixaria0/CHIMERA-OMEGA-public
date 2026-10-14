//! Exact-receipt historical authorization under a reviewer-pinned registry.
//! Key retirement labels and journal timestamps are not trusted time evidence.
use crate::{aether_journal, aether_lattice, encoding, model::State};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const CONTEXT_DOMAIN: &str = "aether/historical-context/v1";
pub const REGISTRY_DOMAIN: &str = "aether/historical-registry/v1";
pub const MAX_KEYS: usize = 16;
pub const MAX_POLICIES: usize = 16;
pub const MAX_AUTHORIZATIONS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Active,
    Retired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Approved,
    Withdrawn,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    id: String,
    public_key_hex: String,
    fingerprint_sha256: String,
    status: KeyStatus,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    id: String,
    policy_revision: u32,
    operation: String,
    executor_id: String,
    deadline_ms: u64,
    policy_sha256: String,
    status: PolicyStatus,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    task_id: String,
    receipt_sha256: String,
    key_id: String,
    policy_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    schema: String,
    source_repository: String,
    lineage_source_revision: String,
    keys: Vec<Key>,
    policies: Vec<Policy>,
    authorizations: Vec<Authorization>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    schema: String,
    source_repository: String,
    source_revision: String,
    registry_digest: String,
    journal_export_digest: String,
    certificate_digest: String,
    journal_head_sha256: String,
    journal_event_count: u64,
}

#[derive(Serialize)]
pub struct HistoricalAuthorization {
    pub role: &'static str,
    pub task_id: String,
    pub receipt_sha256: String,
    pub key_id: String,
    pub signer_fingerprint_sha256: String,
    pub reviewer_key_status: KeyStatus,
    pub policy_id: String,
    pub policy_sha256: String,
    pub policy_revision: u32,
    pub authorization_binding: State,
}

#[derive(Serialize)]
pub struct ProducerView {
    pub selected_signer_fingerprint_sha256: String,
    pub assessment: String,
    pub failed_invariants: Vec<String>,
    pub journal_valid: bool,
    pub authority: &'static str,
}

#[derive(Serialize)]
pub struct HistoricalJournalBinding {
    pub schema: &'static str,
    pub status: State,
    pub scope: &'static str,
    pub context_digest: String,
    pub registry_digest: String,
    pub journal_export_digest: String,
    pub certificate_digest: String,
    pub lineage_evidence_digest: String,
    pub source_repository: &'static str,
    pub lineage_source_revision: &'static str,
    pub journal_export_source_revision: &'static str,
    pub task_id: String,
    pub receipt_sha256: String,
    pub authorizations: Vec<HistoricalAuthorization>,
    pub signature_integrity: State,
    pub raw_operation_binding: State,
    pub selected_policy_binding: State,
    pub registry_authorization_binding: State,
    pub direct_replay_binding: State,
    pub journal_chain_integrity: State,
    pub journal_sequence_integrity: State,
    pub receipt_event_binding: State,
    pub parent_receipt_event_binding: State,
    pub coverage: &'static str,
    pub journal_head_sha256: String,
    pub journal_event_count: u64,
    pub registry_freshness: State,
    pub historical_time_authorization: State,
    pub current_live_key_authorization: State,
    pub external_journal_anchor: State,
    pub independent_observation: State,
    pub producer_binary_attestation: State,
    pub runtime_reproduction: State,
    pub omega_core_verdict: State,
    pub producer_view: ProducerView,
    pub limitations: Vec<&'static str>,
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn id(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing historical binding field {name}"))
}

fn validate_registry(registry: &Registry) -> Result<(), String> {
    if registry.schema != "chimera-aether-trust-registry/v1"
        || registry.source_repository != aether_lattice::AETHER_LATTICE_REPOSITORY
        || registry.lineage_source_revision != aether_lattice::AETHER_LATTICE_REVISION
        || registry.keys.is_empty()
        || registry.keys.len() > MAX_KEYS
        || registry.policies.is_empty()
        || registry.policies.len() > MAX_POLICIES
        || registry.authorizations.is_empty()
        || registry.authorizations.len() > MAX_AUTHORIZATIONS
    {
        return Err("unsupported or unbounded historical registry".into());
    }
    let mut prior = "";
    let mut fingerprints = BTreeSet::new();
    for key in &registry.keys {
        let public = aether_lattice::decode_hex::<32>(&key.public_key_hex)?;
        if !id(&key.id)
            || key.id.as_str() <= prior
            || hash(&public) != key.fingerprint_sha256
            || !fingerprints.insert(&key.fingerprint_sha256)
        {
            return Err("invalid, duplicate or unordered historical key".into());
        }
        prior = &key.id;
    }
    prior = "";
    let mut policy_hashes = BTreeSet::new();
    for policy in &registry.policies {
        let descriptor = aether_lattice::policy_descriptor(
            &policy.operation,
            &policy.executor_id,
            policy.deadline_ms,
        )?;
        if !id(&policy.id)
            || policy.id.as_str() <= prior
            || policy.policy_revision != 1
            || hash(descriptor.as_bytes()) != policy.policy_sha256
            || !policy_hashes.insert(&policy.policy_sha256)
        {
            return Err("invalid, duplicate or unsupported historical policy".into());
        }
        prior = &policy.id;
    }
    prior = "";
    let mut tasks = BTreeSet::new();
    for approval in &registry.authorizations {
        if !aether_lattice::is_uuid(&approval.task_id)
            || !encoding::is_digest(&approval.receipt_sha256)
            || approval.receipt_sha256.as_str() <= prior
            || !tasks.insert(&approval.task_id)
            || !registry.keys.iter().any(|key| key.id == approval.key_id)
            || !registry
                .policies
                .iter()
                .any(|policy| policy.id == approval.policy_id)
        {
            return Err("invalid, duplicate or dangling historical authorization".into());
        }
        prior = &approval.receipt_sha256;
    }
    Ok(())
}

fn authorize(
    registry: &Registry,
    record: &Value,
    role: &'static str,
) -> Result<HistoricalAuthorization, String> {
    if record.get("parent_task_id").is_none() || record["receipt"].get("parent_task_id").is_none() {
        return Err("historical execution requires explicit nullable parent fields".into());
    }
    let receipt = &record["receipt"];
    let receipt_hash = field(receipt, "receipt_sha256")?;
    let task = field(record, "task_id")?;
    let approval = registry
        .authorizations
        .iter()
        .find(|a| a.receipt_sha256 == receipt_hash)
        .ok_or("receipt is not explicitly authorized by selected historical registry")?;
    let key = registry
        .keys
        .iter()
        .find(|k| k.id == approval.key_id)
        .ok_or("missing historical key")?;
    let policy = registry
        .policies
        .iter()
        .find(|p| p.id == approval.policy_id)
        .ok_or("missing historical policy")?;
    if approval.task_id != task
        || key.status == KeyStatus::Revoked
        || policy.status != PolicyStatus::Approved
        || field(&receipt["attestation"], "public_key_hex")? != key.public_key_hex
        || field(&receipt["attestation"], "key_fingerprint_sha256")? != key.fingerprint_sha256
        || field(receipt, "policy_sha256")? != policy.policy_sha256
        || receipt["policy_revision"].as_u64() != Some(u64::from(policy.policy_revision))
        || field(receipt, "operation")? != policy.operation
        || field(receipt, "executor_id")? != policy.executor_id
        || receipt["deadline_ms"].as_u64() != Some(policy.deadline_ms)
    {
        return Err(
            "historical key/policy authorization does not match exact signed receipt".into(),
        );
    }
    Ok(HistoricalAuthorization {
        role,
        task_id: task.into(),
        receipt_sha256: receipt_hash.into(),
        key_id: key.id.clone(),
        signer_fingerprint_sha256: key.fingerprint_sha256.clone(),
        reviewer_key_status: key.status,
        policy_id: policy.id.clone(),
        policy_sha256: policy.policy_sha256.clone(),
        policy_revision: policy.policy_revision,
        authorization_binding: State::Confirmed,
    })
}

/// The external context pin selects the registry and exact evidence checkpoint.
/// Approval is exact-receipt authority, not a timestamp-derived validity period.
pub fn verify_aether_historical_journal(
    export_bytes: &[u8],
    registry_bytes: &[u8],
    context_bytes: &[u8],
    expected_context: &str,
) -> Result<HistoricalJournalBinding, String> {
    let context_value = encoding::parse(context_bytes)?;
    let context_digest = encoding::digest(CONTEXT_DOMAIN, &context_value)?;
    if !encoding::is_digest(expected_context) || context_digest != expected_context {
        return Err("reviewer-pinned historical context digest mismatch".into());
    }
    let context: Context = serde_json::from_value(context_value).map_err(|e| e.to_string())?;
    if context.schema != "chimera-aether-historical-context/v1"
        || context.source_repository != aether_lattice::AETHER_LATTICE_REPOSITORY
        || context.source_revision != aether_journal::EXPORT_REVISION
        || ![
            &context.registry_digest,
            &context.journal_export_digest,
            &context.certificate_digest,
            &context.journal_head_sha256,
        ]
        .into_iter()
        .all(|d| encoding::is_digest(d))
        || !(1..=aether_journal::MAX_EVENTS as u64).contains(&context.journal_event_count)
    {
        return Err("unsupported historical evidence context".into());
    }
    let registry_value = encoding::parse(registry_bytes)?;
    let registry_digest = encoding::digest(REGISTRY_DOMAIN, &registry_value)?;
    if registry_digest != context.registry_digest {
        return Err("selected historical registry digest mismatch".into());
    }
    let registry: Registry = serde_json::from_value(registry_value).map_err(|e| e.to_string())?;
    validate_registry(&registry)?;
    let export = encoding::parse(export_bytes)?;
    let export_digest = encoding::digest(aether_journal::EXPORT_DOMAIN, &export)?;
    if export_digest != context.journal_export_digest {
        return Err("selected historical export digest mismatch".into());
    }
    if export["lineage"].get("parent").is_none() {
        return Err("historical lineage requires explicit parent field".into());
    }
    let child = authorize(&registry, &export["lineage"]["execution"], "execution")?;
    let parent = if export["lineage"]["parent"].is_null() {
        None
    } else {
        Some(authorize(
            &registry,
            &export["lineage"]["parent"],
            "direct_parent",
        )?)
    };
    let checked = aether_lattice::verify_selected_lineage(
        &serde_json::to_vec(&export["lineage"]).map_err(|e| e.to_string())?,
        &aether_lattice::SelectedLineage {
            certificate_digest: context.certificate_digest.clone(),
            journal_head_sha256: context.journal_head_sha256.clone(),
            journal_event_count: context.journal_event_count,
            execution_signer: child.signer_fingerprint_sha256.clone(),
            parent_signer: parent.as_ref().map(|p| p.signer_fingerprint_sha256.clone()),
            require_producer_signer: false,
        },
    )?;
    let journal = aether_journal::verify_selected_journal(
        &export,
        context.journal_event_count,
        &context.journal_head_sha256,
    )?;
    let mut authorizations = vec![child];
    if let Some(parent) = parent {
        authorizations.push(parent);
    }
    Ok(HistoricalJournalBinding {
        schema: "chimera-aether-historical-journal-binding/v1", status: State::Confirmed,
        scope: "EXACT_RECEIPT_REGISTRY_AUTHORIZATION_AND_PINNED_COMPLETE_JOURNAL_ONLY",
        context_digest, registry_digest, journal_export_digest: export_digest,
        certificate_digest: checked.certificate_digest, lineage_evidence_digest: checked.evidence_digest,
        source_repository: aether_lattice::AETHER_LATTICE_REPOSITORY,
        lineage_source_revision: aether_lattice::AETHER_LATTICE_REVISION, journal_export_source_revision: aether_journal::EXPORT_REVISION,
        task_id: checked.task_id, receipt_sha256: checked.receipt_sha256, authorizations,
        signature_integrity: State::Confirmed, raw_operation_binding: State::Confirmed, selected_policy_binding: State::Confirmed,
        registry_authorization_binding: State::Confirmed, direct_replay_binding: checked.direct_replay_binding,
        journal_chain_integrity: State::Confirmed, journal_sequence_integrity: State::Confirmed, receipt_event_binding: State::Confirmed,
        parent_receipt_event_binding: journal.parent_receipt_event_binding, coverage: "GENESIS_TO_PINNED_HEAD",
        journal_head_sha256: context.journal_head_sha256, journal_event_count: context.journal_event_count,
        registry_freshness: State::Unknown, historical_time_authorization: State::Unknown, current_live_key_authorization: State::Unknown,
        external_journal_anchor: State::Unknown, independent_observation: State::Unknown, producer_binary_attestation: State::Unknown,
        runtime_reproduction: State::NotRun, omega_core_verdict: State::NotRun,
        producer_view: ProducerView { selected_signer_fingerprint_sha256: checked.producer_selected_signer,
            assessment: checked.producer_assessment, failed_invariants: checked.producer_failed_invariants,
            journal_valid: checked.producer_journal_valid, authority: "ATTRIBUTED_ONLY" },
        limitations: vec![
            "The reviewer pin selects one registry snapshot and exact checkpoint; registry contents cannot choose their own authority.",
            "Active or retired keys authorize only explicitly listed receipt hashes; revoked keys and withdrawn policies cannot authorize selected receipts.",
            "Execution and direct replay parent may use different approved keys; ancestry beyond that parent is not assessed.",
            "Policy v1 remains bounded to the compiled echo, ASCII-uppercase and UTF-8 SHA-256 semantics; registry entries cannot widen those semantics.",
            "Producer current-key assessments remain attributed and unchanged; successful historical verification does not rewrite the producer's decision.",
            "No timestamp establishes a validity period, compromise time or newest registry; current live-key authority and registry freshness remain UNKNOWN.",
            "The bounded complete chain is relative to the selected head, not canonical global history or an independent external anchor.",
            "Offline verification performs no target execution, public-testnet interaction or upstream operational action.",
        ],
    })
}
