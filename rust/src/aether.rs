//! Strict import boundary for Aether Runtime OS execution receipts.
//!
//! This module validates a caller-pinned, content-addressed Aether receipt and
//! replays its normalized execution lineage against the supported Aether state
//! machine. It intentionally does not re-run worker code, re-check Aether's
//! Ed25519 signatures, authenticate producer build provenance, or promote any
//! OMEGA core verdict dimension.

use crate::encoding;
use serde::{Deserialize, Serialize};

pub const AETHER_REPOSITORY: &str = "aixaria0/Aether-Runtime-OS";
pub const AETHER_CONTRACT_REVISION: &str = "6f59681e31cb77791aea642e81fe2b7026f682f3";
pub const AETHER_RECEIPT_SCHEMA: &str = "aether-execution-receipt/v1";
const AETHER_RECEIPT_SCOPE: &str = "LOCAL_PERSISTED_EXECUTION_JOURNAL_ONLY";
const AETHER_RUNTIME: &str = "aether-runtime-os";
const AETHER_RUNTIME_VERSION: &str = "0.2.0";
const AETHER_STATE_MACHINE: &str = "aether.execution-state-machine/v1";
const AETHER_DIGEST_DOMAIN: &str = "aether-execution-receipt/v1";
const MAX_EVENTS: usize = 64;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AetherEvent {
    index: usize,
    from_state: Option<String>,
    to_state: String,
    worker_id: Option<String>,
    result_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AetherReceipt {
    schema: String,
    scope: String,
    runtime: String,
    runtime_version: String,
    state_machine: String,
    execution_id: String,
    terminal_state: String,
    payload_hash: String,
    result_hash: String,
    worker_id: String,
    events: Vec<AetherEvent>,
    limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AetherImport {
    pub schema: &'static str,
    pub status: &'static str,
    pub scope: &'static str,
    pub repository: &'static str,
    pub supported_revision: &'static str,
    pub receipt_digest: String,
    pub execution_id: String,
    pub terminal_state: String,
    pub payload_hash: String,
    pub result_hash: String,
    pub worker_id: String,
    pub event_count: usize,
    pub replay_status: &'static str,
    pub limitations: Vec<&'static str>,
}

fn allowed_transition(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("Created", "Scheduled")
            | ("Scheduled", "Running")
            | ("Running", "Verifying")
            | ("Verifying", "Completed")
            | ("Running", "Failed")
            | ("Failed", "Recovering")
            | ("Recovering", "Verifying")
    )
}

fn validate_receipt(receipt: &AetherReceipt) -> Result<(), String> {
    if receipt.schema != AETHER_RECEIPT_SCHEMA
        || receipt.scope != AETHER_RECEIPT_SCOPE
        || receipt.runtime != AETHER_RUNTIME
        || receipt.runtime_version != AETHER_RUNTIME_VERSION
        || receipt.state_machine != AETHER_STATE_MACHINE
    {
        return Err("unsupported Aether receipt contract".into());
    }
    if receipt.execution_id.is_empty() || receipt.worker_id.is_empty() {
        return Err("Aether receipt is missing execution or worker identity".into());
    }
    if receipt.terminal_state != "Completed" {
        return Err("Aether receipt must represent a Completed execution".into());
    }
    if !encoding::is_digest(&receipt.payload_hash) || !encoding::is_digest(&receipt.result_hash) {
        return Err("Aether receipt contains an invalid payload or result digest".into());
    }
    if receipt.limitations.is_empty() {
        return Err("Aether receipt must preserve explicit limitations".into());
    }
    if receipt.events.is_empty() || receipt.events.len() > MAX_EVENTS {
        return Err("Aether receipt has an invalid event count".into());
    }

    let first = &receipt.events[0];
    if first.index != 0 || first.from_state.is_some() || first.to_state != "Created" {
        return Err("Aether receipt must begin by materializing Created".into());
    }
    if first.worker_id.is_some() || first.result_hash.is_some() {
        return Err("Created event must not claim a worker or result".into());
    }

    let mut current = "Created";
    for (index, event) in receipt.events.iter().enumerate().skip(1) {
        if event.index != index {
            return Err(format!("Aether event index diverges at {index}"));
        }
        if event.from_state.as_deref() != Some(current) {
            return Err(format!("Aether lineage diverges at event {index}"));
        }
        if !allowed_transition(current, &event.to_state) {
            return Err(format!(
                "Aether transition {current} -> {} is not allowed",
                event.to_state
            ));
        }
        if event.worker_id.as_deref() != Some(receipt.worker_id.as_str()) {
            return Err(format!("Aether worker binding diverges at event {index}"));
        }

        match event.to_state.as_str() {
            "Verifying" | "Completed" => {
                if event.result_hash.as_deref() != Some(receipt.result_hash.as_str()) {
                    return Err(format!("Aether result binding diverges at event {index}"));
                }
            }
            _ if event.result_hash.is_some() => {
                return Err(format!(
                    "Aether result digest appears too early at event {index}"
                ));
            }
            _ => {}
        }
        current = &event.to_state;
    }

    let last = receipt.events.last().expect("events checked non-empty");
    if current != "Completed" || last.result_hash.as_deref() != Some(receipt.result_hash.as_str()) {
        return Err("Aether terminal event is not bound to the receipt result digest".into());
    }
    Ok(())
}

/// Imports an Aether receipt only when the caller pins both the receipt digest
/// and the exact Aether contract revision supported by this importer.
pub fn import_aether_receipt(
    receipt_bytes: &[u8],
    expected_receipt_digest: &str,
    expected_source_revision: &str,
) -> Result<AetherImport, String> {
    if expected_source_revision != AETHER_CONTRACT_REVISION {
        return Err("caller-pinned Aether source revision is unsupported".into());
    }
    if !encoding::is_digest(expected_receipt_digest) {
        return Err("invalid caller-pinned Aether receipt digest".into());
    }

    let value = encoding::parse(receipt_bytes)?;
    let actual_digest = encoding::digest(AETHER_DIGEST_DOMAIN, &value)?;
    if actual_digest != expected_receipt_digest {
        return Err("caller-pinned Aether receipt digest mismatch".into());
    }
    let receipt: AetherReceipt = serde_json::from_value(value).map_err(|e| e.to_string())?;
    validate_receipt(&receipt)?;

    Ok(AetherImport {
        schema: "chimera-aether-runtime-import/v1",
        status: "IMPORTED_NOT_OMEGA_VERIFIED",
        scope: "PINNED_AETHER_RECEIPT_AND_LINEAGE_BINDING_ONLY",
        repository: AETHER_REPOSITORY,
        supported_revision: AETHER_CONTRACT_REVISION,
        receipt_digest: actual_digest,
        execution_id: receipt.execution_id,
        terminal_state: receipt.terminal_state,
        payload_hash: receipt.payload_hash,
        result_hash: receipt.result_hash,
        worker_id: receipt.worker_id,
        event_count: receipt.events.len(),
        replay_status: "LINEAGE_REPLAY_VALID",
        limitations: vec![
            "OMEGA replays only the normalized Aether receipt lineage; it does not re-run Aether worker code.",
            "The receipt omits worker Ed25519 signatures, so OMEGA does not independently authenticate worker identity or result bytes.",
            "The pinned source revision identifies the supported receipt contract, not authenticated build provenance of the producer binary.",
            "A self-consistently forged receipt can remain internally valid if the caller also trusts its digest; digest provenance must be established outside this importer.",
            "No OMEGA core verdict dimension is promoted by this import.",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(recovery: bool) -> Vec<u8> {
        let result = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let payload = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let events = if recovery {
            json!([
                {"index":0,"from_state":null,"to_state":"Created","worker_id":null,"result_hash":null},
                {"index":1,"from_state":"Created","to_state":"Scheduled","worker_id":"worker-2","result_hash":null},
                {"index":2,"from_state":"Scheduled","to_state":"Running","worker_id":"worker-2","result_hash":null},
                {"index":3,"from_state":"Running","to_state":"Failed","worker_id":"worker-2","result_hash":null},
                {"index":4,"from_state":"Failed","to_state":"Recovering","worker_id":"worker-2","result_hash":null},
                {"index":5,"from_state":"Recovering","to_state":"Verifying","worker_id":"worker-2","result_hash":result},
                {"index":6,"from_state":"Verifying","to_state":"Completed","worker_id":"worker-2","result_hash":result}
            ])
        } else {
            json!([
                {"index":0,"from_state":null,"to_state":"Created","worker_id":null,"result_hash":null},
                {"index":1,"from_state":"Created","to_state":"Scheduled","worker_id":"worker-1","result_hash":null},
                {"index":2,"from_state":"Scheduled","to_state":"Running","worker_id":"worker-1","result_hash":null},
                {"index":3,"from_state":"Running","to_state":"Verifying","worker_id":"worker-1","result_hash":result},
                {"index":4,"from_state":"Verifying","to_state":"Completed","worker_id":"worker-1","result_hash":result}
            ])
        };
        let worker = if recovery { "worker-2" } else { "worker-1" };
        serde_json::to_vec(&json!({
            "schema": AETHER_RECEIPT_SCHEMA,
            "scope": AETHER_RECEIPT_SCOPE,
            "runtime": AETHER_RUNTIME,
            "runtime_version": AETHER_RUNTIME_VERSION,
            "state_machine": AETHER_STATE_MACHINE,
            "execution_id": "exec-1",
            "terminal_state": "Completed",
            "payload_hash": payload,
            "result_hash": result,
            "worker_id": worker,
            "events": events,
            "limitations": ["fixture limitation"]
        }))
        .unwrap()
    }

    fn pin(bytes: &[u8]) -> String {
        let value = encoding::parse(bytes).unwrap();
        encoding::digest(AETHER_DIGEST_DOMAIN, &value).unwrap()
    }

    #[test]
    fn imports_normal_and_recovery_lineages_without_promoting_authority() {
        for bytes in [fixture(false), fixture(true)] {
            let imported = import_aether_receipt(&bytes, &pin(&bytes), AETHER_CONTRACT_REVISION)
                .expect("valid receipt must import");
            assert_eq!(imported.status, "IMPORTED_NOT_OMEGA_VERIFIED");
            assert_eq!(imported.replay_status, "LINEAGE_REPLAY_VALID");
        }
    }

    #[test]
    fn rejects_digest_and_source_pin_mismatch() {
        let bytes = fixture(false);
        let wrong = "0".repeat(64);
        assert!(import_aether_receipt(&bytes, &wrong, AETHER_CONTRACT_REVISION).is_err());
        assert!(import_aether_receipt(&bytes, &pin(&bytes), &"f".repeat(40)).is_err());
    }

    #[test]
    fn rejects_rehashed_lineage_mutation() {
        let bytes = fixture(false);
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["events"][2]["from_state"] = json!("Ghost");
        let mutated = serde_json::to_vec(&value).unwrap();
        assert!(import_aether_receipt(&mutated, &pin(&mutated), AETHER_CONTRACT_REVISION).is_err());
    }
}
