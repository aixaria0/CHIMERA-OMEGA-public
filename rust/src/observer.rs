use crate::{
    adapter::{verify_kv_receipt, KvReceipt, KV_RECEIPT_SCHEMA},
    encoding,
    model::{Overall, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const KV_OBSERVER_RECEIPT_SCHEMA: &str = "chimera-kv-observer-receipt/v1";
pub const KV_OBSERVER_BINDING_SCHEMA: &str = "chimera-kv-observer-binding-report/v1";
const KV_EXECUTION_RECEIPT_SCOPE: &str = "LOCAL_DETERMINISTIC_ADAPTER_EXECUTION_ONLY";
pub const KV_OBSERVER_SCOPE: &str = "LOCAL_KV_ARTIFACT_OBSERVER_ONLY";
const KV_OBSERVER_BINDING_SCOPE: &str = "KV_OBSERVER_ARTIFACT_TO_PINNED_PACKAGE_BINDING_ONLY";
pub const KV_OBSERVER_ID: &str = "omega-kv-observer";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_STATE_KEYS: usize = 256;
const MAX_SNAPSHOTS: usize = 257;

type KvState = BTreeMap<String, u64>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KvObserverReceipt {
    pub schema: String,
    pub scope: String,
    pub observer_id: String,
    pub execution_receipt_digest: String,
    pub observer_source_digest: String,
    pub observer_contract_digest: String,
    pub snapshot_count: usize,
    pub observed_commitments: Vec<String>,
    pub observation_digest: String,
    pub limitations: Vec<String>,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct KvObserverBindingReport {
    pub schema: String,
    pub status: State,
    pub scope: String,
    pub package_digest: String,
    pub execution_receipt_digest: String,
    pub observer_receipt_digest: String,
    pub observation_digest: String,
    pub observed_evidence_id: String,
    pub snapshot_count: usize,
    pub claim_status: Overall,
    pub independent_observation: State,
    pub limitations: Vec<String>,
}

fn valid_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && !value.bytes().any(|b| b.is_ascii_control())
}

fn validate_state(state: &KvState) -> Result<(), String> {
    if state.len() > MAX_STATE_KEYS {
        return Err("observer KV state exceeds 256 keys".into());
    }
    for (key, value) in state {
        if !valid_key(key) {
            return Err(format!("observer invalid KV key: {key:?}"));
        }
        if *value > MAX_SAFE_INTEGER {
            return Err(format!("observer unsafe KV integer at key {key:?}"));
        }
    }
    Ok(())
}

fn state_digest(state: &KvState) -> Result<String, String> {
    encoding::digest(
        "adapter/kv-state/v1",
        &serde_json::to_value(state).map_err(|e| e.to_string())?,
    )
}

fn execution_receipt_digest(receipt: &KvReceipt) -> Result<String, String> {
    let mut value = serde_json::to_value(receipt).map_err(|e| e.to_string())?;
    value
        .as_object_mut()
        .ok_or("KV execution receipt must be an object")?
        .remove("digest");
    encoding::digest("adapter/kv-receipt/v1", &value)
}

fn observer_source_digest() -> Result<String, String> {
    encoding::digest(
        "observer/kv-source/v1",
        &Value::String(include_str!("observer.rs").to_owned()),
    )
}

fn observer_contract_digest() -> Result<String, String> {
    encoding::digest(
        "observer/kv-contract/v1",
        &json!({
            "input": "chimera-kv-execution-receipt/v1",
            "observation": "recompute-each-raw-snapshot-state-commitment",
            "state_digest_domain": "adapter/kv-state/v1",
            "ordering": "contiguous-snapshot-index",
            "external_io": "none",
            "claim_authority": "none"
        }),
    )
}

fn observation_digest(
    execution_receipt_digest: &str,
    commitments: &[String],
) -> Result<String, String> {
    encoding::digest(
        "observer/kv-observation/v1",
        &json!({
            "execution_receipt_digest": execution_receipt_digest,
            "observed_commitments": commitments
        }),
    )
}

fn observer_receipt_digest(receipt: &KvObserverReceipt) -> Result<String, String> {
    let mut value = serde_json::to_value(receipt).map_err(|e| e.to_string())?;
    value
        .as_object_mut()
        .ok_or("KV observer receipt must be an object")?
        .remove("digest");
    encoding::digest("observer/kv-receipt/v1", &value)
}

/// Re-observes raw snapshots from a supplied KV execution receipt through a code path
/// separate from the producer adapter. This observes an artifact, not a live target.
pub fn observe_kv(receipt_input: &[u8]) -> Result<KvObserverReceipt, String> {
    let receipt: KvReceipt =
        serde_json::from_value(encoding::parse(receipt_input)?).map_err(|e| e.to_string())?;
    if receipt.schema != KV_RECEIPT_SCHEMA {
        return Err("observer unsupported KV execution receipt schema".into());
    }
    if receipt.scope != KV_EXECUTION_RECEIPT_SCOPE {
        return Err("observer unexpected KV execution receipt scope".into());
    }
    if !encoding::is_digest(&receipt.digest) {
        return Err("observer malformed KV execution receipt digest".into());
    }
    if receipt.snapshots.is_empty() || receipt.snapshots.len() > MAX_SNAPSHOTS {
        return Err("observer requires 1..257 KV snapshots".into());
    }
    let recomputed_execution_digest = execution_receipt_digest(&receipt)?;
    if receipt.digest != recomputed_execution_digest {
        return Err("observer KV execution receipt digest mismatch".into());
    }

    let mut commitments = Vec::with_capacity(receipt.snapshots.len());
    for (index, snapshot) in receipt.snapshots.iter().enumerate() {
        if snapshot.index != index {
            return Err(format!("observer snapshot index mismatch at {index}"));
        }
        validate_state(&snapshot.state)?;
        if !encoding::is_digest(&snapshot.digest) {
            return Err(format!("observer malformed snapshot digest at {index}"));
        }
        let recomputed = state_digest(&snapshot.state)?;
        if snapshot.digest != recomputed {
            return Err(format!("observer snapshot digest mismatch at {index}"));
        }
        commitments.push(recomputed);
    }

    let source_digest = observer_source_digest()?;
    let contract_digest = observer_contract_digest()?;
    let observation_digest = observation_digest(&receipt.digest, &commitments)?;
    let mut observer_receipt = KvObserverReceipt {
        schema: KV_OBSERVER_RECEIPT_SCHEMA.into(),
        scope: KV_OBSERVER_SCOPE.into(),
        observer_id: KV_OBSERVER_ID.into(),
        execution_receipt_digest: receipt.digest,
        observer_source_digest: source_digest,
        observer_contract_digest: contract_digest,
        snapshot_count: commitments.len(),
        observed_commitments: commitments,
        observation_digest,
        limitations: vec![
            "This observer re-observes a supplied execution artifact; it does not observe a live target or external system.".into(),
            "The observer identity is not cryptographically authenticated and does not establish organizational or machine independence.".into(),
            "The observer shares OMEGA's canonical encoding and SHA-256 implementation; code-path separation is not implementation diversity.".into(),
            "This receipt cannot promote the independent_observation verdict dimension by itself.".into(),
        ],
        digest: String::new(),
    };
    observer_receipt.digest = observer_receipt_digest(&observer_receipt)?;
    Ok(observer_receipt)
}

/// Binds a separately produced observer artifact to the same raw execution receipt and
/// externally pinned evidence package. Independent-observation authority remains UNKNOWN.
pub fn verify_kv_observer(
    package_input: &[u8],
    expected_package_digest: &str,
    execution_receipt_input: &[u8],
    observer_receipt_input: &[u8],
    expected_observer_digest: &str,
) -> Result<KvObserverBindingReport, String> {
    if !encoding::is_digest(expected_observer_digest) {
        return Err("a caller-supplied observer receipt digest pin is required".into());
    }
    let kv_binding = verify_kv_receipt(
        package_input,
        expected_package_digest,
        execution_receipt_input,
    )?;
    let supplied: KvObserverReceipt =
        serde_json::from_value(encoding::parse(observer_receipt_input)?)
            .map_err(|e| e.to_string())?;
    if supplied.schema != KV_OBSERVER_RECEIPT_SCHEMA {
        return Err("unsupported KV observer receipt schema".into());
    }
    if supplied.scope != KV_OBSERVER_SCOPE || supplied.observer_id != KV_OBSERVER_ID {
        return Err("KV observer receipt boundary mismatch".into());
    }
    if !encoding::is_digest(&supplied.digest)
        || !encoding::is_digest(&supplied.execution_receipt_digest)
        || !encoding::is_digest(&supplied.observer_source_digest)
        || !encoding::is_digest(&supplied.observer_contract_digest)
        || !encoding::is_digest(&supplied.observation_digest)
    {
        return Err("malformed KV observer digest".into());
    }
    if supplied.digest != expected_observer_digest {
        return Err("caller observer pin mismatch".into());
    }
    if supplied.execution_receipt_digest != kv_binding.receipt_digest {
        return Err("observer/execution receipt binding mismatch".into());
    }

    let recomputed = observe_kv(execution_receipt_input)?;
    let supplied_value = serde_json::to_value(&supplied).map_err(|e| e.to_string())?;
    let recomputed_value = serde_json::to_value(&recomputed).map_err(|e| e.to_string())?;
    if encoding::canonical_json(&supplied_value)? != encoding::canonical_json(&recomputed_value)? {
        return Err("KV observer receipt does not match deterministic recomputation".into());
    }

    Ok(KvObserverBindingReport {
        schema: KV_OBSERVER_BINDING_SCHEMA.into(),
        status: State::Confirmed,
        scope: KV_OBSERVER_BINDING_SCOPE.into(),
        package_digest: kv_binding.package_digest,
        execution_receipt_digest: kv_binding.receipt_digest,
        observer_receipt_digest: supplied.digest,
        observation_digest: supplied.observation_digest,
        observed_evidence_id: kv_binding.observed_evidence_id,
        snapshot_count: supplied.snapshot_count,
        claim_status: kv_binding.claim_status,
        independent_observation: State::Unknown,
        limitations: vec![
            "This confirms deterministic binding of a separately produced observer artifact to the raw execution receipt and pinned package.".into(),
            "The independent_observation dimension remains UNKNOWN because process, host, operator, key ownership, and organizational independence are not authenticated by this artifact.".into(),
            "A matching observer receipt establishes artifact-level corroboration, not live-target truth, production reachability, consensus/finality, or physical validity.".into(),
        ],
    })
}
