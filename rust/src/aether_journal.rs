//! Complete bounded journal verification under an externally pinned context.
//! A selected hash-chain head is not an independent or externally anchored history.
use crate::{
    aether_lattice::{self, AetherLineageBinding},
    encoding,
    model::State,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

pub const EXPORT_REVISION: &str = "30dad8ec794e3f27600bfc0a5a5df072e79ba8c4";
pub const CONTEXT_DOMAIN: &str = "aether/journal-context/v1";
pub const EXPORT_DOMAIN: &str = "aether/journal-export/v1";
pub const MAX_EVENTS: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    schema: String,
    source_repository: String,
    source_revision: String,
    lineage_context: Value,
    journal_export_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    schema: String,
    lineage: Value,
    journal: Journal,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: String,
    coverage: String,
    events: Vec<Event>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    sequence: u64,
    event_id: String,
    task_id: String,
    event_type: String,
    timestamp_ns_decimal: String,
    payload_json: String,
    previous_hash: Option<String>,
    event_hash: String,
}

#[derive(Serialize)]
pub struct AetherJournalBinding {
    pub schema: &'static str,
    pub status: State,
    pub scope: &'static str,
    pub context_digest: String,
    pub journal_export_digest: String,
    pub export_source_revision: &'static str,
    pub coverage: &'static str,
    pub journal_event_count: u64,
    pub journal_head_sha256: String,
    pub journal_chain_integrity: State,
    pub journal_sequence_integrity: State,
    pub receipt_event_binding: State,
    pub parent_receipt_event_binding: State,
    pub external_journal_anchor: State,
    pub independent_observation: State,
    pub producer_binary_attestation: State,
    pub omega_core_verdict: State,
    pub runtime_reproduction: State,
    pub lineage_binding: AetherLineageBinding,
    pub limitations: Vec<&'static str>,
}

fn timestamp(text: &str) -> Result<(), String> {
    let n = text
        .parse::<u64>()
        .map_err(|_| "invalid journal timestamp decimal")?;
    if n == 0 || n > i64::MAX as u64 || n.to_string() != text {
        return Err("journal timestamp must be canonical positive SQLite-range decimal".into());
    }
    Ok(())
}

fn event_hash(event: &Event) -> String {
    let mut hash = Sha256::new();
    for part in [
        event.previous_hash.as_deref().unwrap_or(""),
        &event.event_id,
        &event.task_id,
        &event.event_type,
        &event.timestamp_ns_decimal,
        &event.payload_json,
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    format!("{:x}", hash.finalize())
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing authenticated field {key}"))
}

fn receipt_events(
    events: &[Event],
    payloads: &[BTreeMap<String, String>],
    execution: &Value,
) -> Result<(), String> {
    let task = field(execution, "task_id")?;
    let receipt = &execution["receipt"];
    let digest = field(receipt, "receipt_sha256")?;
    let attestation = &receipt["attestation"];
    let signed: Vec<_> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| e.task_id == task && e.event_type == "RECEIPT_SIGNED")
        .collect();
    let verified: Vec<_> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| e.task_id == task && e.event_type == "VERIFICATION_PASSED")
        .collect();
    if signed.len() != 1 || verified.len() != 1 {
        return Err(
            "journal requires unique signed/verified events for each selected receipt".into(),
        );
    }
    let (si, s) = signed[0];
    let (vi, v) = verified[0];
    let expected_signed = BTreeMap::from([
        ("algorithm".into(), field(attestation, "algorithm")?.into()),
        (
            "signer_fingerprint".into(),
            field(attestation, "key_fingerprint_sha256")?.into(),
        ),
        ("receipt_sha256".into(), digest.into()),
    ]);
    let expected_verified = BTreeMap::from([
        ("executor_id".into(), field(receipt, "executor_id")?.into()),
        ("receipt_sha256".into(), digest.into()),
    ]);
    if v.sequence <= s.sequence
        || payloads[si] != expected_signed
        || payloads[vi] != expected_verified
    {
        return Err("journal signed/verified receipt event binding or order mismatch".into());
    }
    Ok(())
}

pub(crate) struct JournalCheck {
    pub parent_receipt_event_binding: State,
}

fn verify_export_chain(
    export: &Export,
    selected_count: u64,
    selected_head: &str,
) -> Result<JournalCheck, String> {
    if export.journal.events.len() as u64 != selected_count {
        return Err("journal coverage count mismatch".into());
    }
    let mut previous: Option<&str> = None;
    let mut ids = HashSet::new();
    let mut payloads = Vec::new();
    for (index, event) in export.journal.events.iter().enumerate() {
        timestamp(&event.timestamp_ns_decimal)?;
        if event.sequence != index as u64 + 1
            || !aether_lattice::is_uuid(&event.event_id)
            || !aether_lattice::is_uuid(&event.task_id)
            || !ids.insert(event.event_id.as_str())
            || !encoding::is_digest(&event.event_hash)
            || event.previous_hash.as_deref() != previous
            || event_hash(event) != event.event_hash
        {
            return Err("journal sequence, identity, hash or continuity mismatch".into());
        }
        let payload: BTreeMap<String, String> =
            serde_json::from_value(encoding::parse(event.payload_json.as_bytes())?)
                .map_err(|e| e.to_string())?;
        if serde_json::to_string(&payload).map_err(|e| e.to_string())? != event.payload_json {
            return Err("journal payload is not the reviewed canonical string-map encoding".into());
        }
        payloads.push(payload);
        previous = Some(&event.event_hash);
    }
    if previous != Some(selected_head) {
        return Err("journal head differs from selected checkpoint".into());
    }
    receipt_events(
        &export.journal.events,
        &payloads,
        &export.lineage["execution"],
    )?;
    let parent_receipt_event_binding = if export.lineage["parent"].is_null() {
        State::NotApplicable
    } else {
        receipt_events(&export.journal.events, &payloads, &export.lineage["parent"])?;
        State::Confirmed
    };
    Ok(JournalCheck {
        parent_receipt_event_binding,
    })
}

/// Used only after the selected execution and direct parent are authenticated.
pub(crate) fn verify_selected_journal(
    export_value: &Value,
    selected_count: u64,
    selected_head: &str,
) -> Result<JournalCheck, String> {
    if export_value["lineage"].get("parent").is_none()
        || export_value["lineage"]["execution"]
            .get("parent_task_id")
            .is_none()
        || export_value["journal"]["events"]
            .as_array()
            .is_some_and(|events| {
                events
                    .iter()
                    .any(|event| event.get("previous_hash").is_none())
            })
    {
        return Err("journal export requires explicit nullable evidence fields".into());
    }
    let export: Export = serde_json::from_value(export_value.clone()).map_err(|e| e.to_string())?;
    if export.schema != "aether-journal-export/v1"
        || export.journal.schema != "aether-journal-events/v1"
        || export.journal.coverage != "genesis_to_snapshot_head"
        || export.journal.events.is_empty()
        || export.journal.events.len() > MAX_EVENTS
    {
        return Err("unsupported or incomplete bounded journal coverage".into());
    }
    verify_export_chain(&export, selected_count, selected_head)
}

pub fn verify_aether_journal(
    export_bytes: &[u8],
    context_bytes: &[u8],
    expected_context_digest: &str,
) -> Result<AetherJournalBinding, String> {
    if !encoding::is_digest(expected_context_digest) {
        return Err("invalid external journal context pin".into());
    }
    let context_value = encoding::parse(context_bytes)?;
    let context_digest = encoding::digest(CONTEXT_DOMAIN, &context_value)?;
    if context_digest != expected_context_digest {
        return Err("caller-pinned journal context digest mismatch".into());
    }
    let context: Context = serde_json::from_value(context_value).map_err(|e| e.to_string())?;
    if context.schema != "chimera-aether-journal-context/v1"
        || context.source_repository != aether_lattice::AETHER_LATTICE_REPOSITORY
        || context.source_revision != EXPORT_REVISION
        || !encoding::is_digest(&context.journal_export_digest)
    {
        return Err("unsupported journal export verifier context".into());
    }
    let export_value = encoding::parse(export_bytes)?;
    // Serde treats missing Option fields as None; this wire format requires
    // explicit nulls so omissions cannot silently normalize the source evidence.
    if export_value["lineage"].get("parent").is_none()
        || export_value["lineage"]["execution"]
            .get("parent_task_id")
            .is_none()
        || export_value["journal"]["events"]
            .as_array()
            .is_some_and(|events| {
                events
                    .iter()
                    .any(|event| event.get("previous_hash").is_none())
            })
    {
        return Err("journal export requires explicit nullable evidence fields".into());
    }
    let journal_export_digest = encoding::digest(EXPORT_DOMAIN, &export_value)?;
    if journal_export_digest != context.journal_export_digest {
        return Err("caller-pinned journal export digest mismatch".into());
    }
    let export: Export = serde_json::from_value(export_value).map_err(|e| e.to_string())?;
    if export.schema != "aether-journal-export/v1"
        || export.journal.schema != "aether-journal-events/v1"
        || export.journal.coverage != "genesis_to_snapshot_head"
        || export.journal.events.is_empty()
        || export.journal.events.len() > MAX_EVENTS
    {
        return Err("unsupported or incomplete bounded journal coverage".into());
    }
    let lineage_pin = encoding::digest(aether_lattice::CONTEXT_DOMAIN, &context.lineage_context)?;
    let lineage_binding = aether_lattice::verify_aether_lineage(
        &serde_json::to_vec(&export.lineage).map_err(|e| e.to_string())?,
        &serde_json::to_vec(&context.lineage_context).map_err(|e| e.to_string())?,
        &lineage_pin,
    )?;
    let selected_count = context.lineage_context["journal_event_count"]
        .as_u64()
        .ok_or("missing selected journal count")?;
    let selected_head = field(&context.lineage_context, "journal_head_sha256")?;
    let checked_journal = verify_export_chain(&export, selected_count, selected_head)?;
    Ok(AetherJournalBinding {
        schema:"chimera-aether-journal-binding/v1",status:State::Confirmed,
        scope:"SIGNED_AETHER_OPERATION_AND_PINNED_COMPLETE_JOURNAL_BINDING_ONLY",
        context_digest,journal_export_digest,export_source_revision:EXPORT_REVISION,
        coverage:"GENESIS_TO_PINNED_HEAD",journal_event_count:selected_count,journal_head_sha256:selected_head.into(),
        journal_chain_integrity:State::Confirmed,journal_sequence_integrity:State::Confirmed,
        receipt_event_binding:State::Confirmed,parent_receipt_event_binding:checked_journal.parent_receipt_event_binding,
        external_journal_anchor:State::Unknown,independent_observation:State::Unknown,
        producer_binary_attestation:State::Unknown,omega_core_verdict:State::NotRun,runtime_reproduction:State::NotRun,
        lineage_binding,limitations:vec![
            "Completeness means genesis through the caller-selected head/count, within 256 events and OMEGA's 1 MiB JSON profile; partial history is rejected.",
            "Journal hashes authenticate continuity against the selected checkpoint, not objective history, freshness, key custody or an independent external anchor.",
            "Timestamps are exact hashed decimal strings, not independently attested execution times.",
            "The nested lineage_binding is the unchanged first-stage report; its journal UNKNOWN describes that stage. This report separately verifies the exported chain and selected receipt events.",
            "Only the selected execution and authenticated direct parent receive receipt-event binding checks; other events have hash/encoding checks, not application-level verdicts.",
            "Source pins select reviewed semantics; binary attestation, independent observation and external anchoring remain UNKNOWN; core OMEGA verdict and target execution remain NOT_RUN.",
        ],
    })
}
