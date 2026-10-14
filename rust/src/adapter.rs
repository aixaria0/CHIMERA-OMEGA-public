use crate::{encoding, model::*, seal, verify};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const KV_SCENARIO_SCHEMA: &str = "chimera-kv-scenario/v1";
pub const KV_RECEIPT_SCHEMA: &str = "chimera-kv-execution-receipt/v1";
pub const KV_RECEIPT_BINDING_SCHEMA: &str = "chimera-kv-receipt-binding-report/v1";
const KV_RECEIPT_SCOPE: &str = "LOCAL_DETERMINISTIC_ADAPTER_EXECUTION_ONLY";
const KV_BINDING_SCOPE: &str = "KV_RAW_SNAPSHOT_TO_PINNED_PACKAGE_BINDING_ONLY";
const KV_TARGET_SYSTEM: &str = "omega-kv-machine";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_STATE_KEYS: usize = 256;
const MAX_STEPS: usize = 256;
const MAX_SNAPSHOTS: usize = MAX_STEPS + 1;

pub type KvState = BTreeMap<String, u64>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KvScenario {
    pub schema: String,
    pub id: String,
    pub initial: KvState,
    pub steps: Vec<KvStep>,
    pub expected: Vec<KvState>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KvStep {
    Put { key: String, value: u64 },
    Add { key: String, delta: u64 },
    Delete { key: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KvSnapshot {
    pub index: usize,
    pub state: KvState,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KvReceipt {
    pub schema: String,
    pub scope: String,
    pub scenario_id: String,
    pub scenario_digest: String,
    pub adapter_source_digest: String,
    pub execution_contract_digest: String,
    pub package_digest: String,
    pub snapshots: Vec<KvSnapshot>,
    pub limitations: Vec<String>,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct KvExecution {
    pub package: Envelope,
    pub receipt: KvReceipt,
}

#[derive(Clone, Debug, Serialize)]
pub struct KvReceiptBindingReport {
    pub schema: String,
    pub status: State,
    pub scope: String,
    pub package_digest: String,
    pub receipt_digest: String,
    pub observed_evidence_id: String,
    pub snapshot_count: usize,
    pub claim_status: Overall,
    pub limitations: Vec<String>,
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn valid_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && !value.bytes().any(|b| b.is_ascii_control())
}

fn validate_state(state: &KvState) -> Result<(), String> {
    if state.len() > MAX_STATE_KEYS {
        return Err("KV state exceeds 256 keys".into());
    }
    for (key, value) in state {
        if !valid_key(key) {
            return Err(format!("invalid KV key: {key:?}"));
        }
        if *value > MAX_SAFE_INTEGER {
            return Err(format!("unsafe KV integer at key {key:?}"));
        }
    }
    Ok(())
}

fn validate_scenario(scenario: &KvScenario) -> Result<(), String> {
    if scenario.schema != KV_SCENARIO_SCHEMA {
        return Err("unsupported KV scenario schema".into());
    }
    if !valid_identifier(&scenario.id) {
        return Err("invalid KV scenario id".into());
    }
    if scenario.steps.len() > MAX_STEPS {
        return Err("KV scenario exceeds 256 steps".into());
    }
    if scenario.expected.len() != scenario.steps.len() + 1 {
        return Err("expected snapshots must include initial state and one state per step".into());
    }
    validate_state(&scenario.initial)?;
    for state in &scenario.expected {
        validate_state(state)?;
    }
    for step in &scenario.steps {
        match step {
            KvStep::Put { key, value } => {
                if !valid_key(key) || *value > MAX_SAFE_INTEGER {
                    return Err("invalid KV put step".into());
                }
            }
            KvStep::Add { key, delta } => {
                if !valid_key(key) || *delta > MAX_SAFE_INTEGER {
                    return Err("invalid KV add step".into());
                }
            }
            KvStep::Delete { key } => {
                if !valid_key(key) {
                    return Err("invalid KV delete step".into());
                }
            }
        }
    }
    Ok(())
}

fn execute(scenario: &KvScenario) -> Result<Vec<KvState>, String> {
    let mut state = scenario.initial.clone();
    let mut snapshots = vec![state.clone()];
    for (index, step) in scenario.steps.iter().enumerate() {
        match step {
            KvStep::Put { key, value } => {
                state.insert(key.clone(), *value);
            }
            KvStep::Add { key, delta } => {
                let current = state
                    .get_mut(key)
                    .ok_or_else(|| format!("step {index}: add references absent key {key:?}"))?;
                *current = current
                    .checked_add(*delta)
                    .filter(|value| *value <= MAX_SAFE_INTEGER)
                    .ok_or_else(|| {
                        format!("step {index}: KV addition exceeds safe integer range")
                    })?;
            }
            KvStep::Delete { key } => {
                if state.remove(key).is_none() {
                    return Err(format!(
                        "step {index}: delete references absent key {key:?}"
                    ));
                }
            }
        }
        validate_state(&state)?;
        snapshots.push(state.clone());
    }
    Ok(snapshots)
}

fn state_digest(state: &KvState) -> Result<String, String> {
    encoding::digest(
        "adapter/kv-state/v1",
        &serde_json::to_value(state).map_err(|e| e.to_string())?,
    )
}

fn adapter_source_digest() -> Result<String, String> {
    encoding::digest(
        "adapter/kv-source/v1",
        &Value::String(include_str!("adapter.rs").to_owned()),
    )
}

fn execution_contract_digest() -> Result<String, String> {
    encoding::digest(
        "adapter/kv-execution-contract/v1",
        &json!({
            "machine": "bounded-ascii-u64-kv",
            "state_order": "lexicographic-key",
            "integer_range": "0..9007199254740991",
            "put": "set-key-to-value",
            "add": "checked-add-existing-key",
            "delete": "remove-existing-key",
            "external_io": "none"
        }),
    )
}

fn mutation_for(value: &str) -> String {
    let zero = "0".repeat(64);
    if value == zero {
        "1".repeat(64)
    } else {
        zero
    }
}

fn receipt_digest(receipt: &KvReceipt) -> Result<String, String> {
    let mut value = serde_json::to_value(receipt).map_err(|e| e.to_string())?;
    value
        .as_object_mut()
        .ok_or("KV receipt must be an object")?
        .remove("digest");
    encoding::digest("adapter/kv-receipt/v1", &value)
}

/// Executes a bounded deterministic KV state machine and authors an existing v2
/// evidence envelope. The adapter does not promote any verifier dimension.
pub fn run_kv(input: &[u8]) -> Result<KvExecution, String> {
    let parsed = encoding::parse(input)?;
    let scenario_digest = encoding::digest("adapter/kv-scenario/v1", &parsed)?;
    let scenario: KvScenario = serde_json::from_value(parsed).map_err(|e| e.to_string())?;
    validate_scenario(&scenario)?;

    let observed_states = execute(&scenario)?;
    let expected_digests = scenario
        .expected
        .iter()
        .map(state_digest)
        .collect::<Result<Vec<_>, _>>()?;
    let observed_digests = observed_states
        .iter()
        .map(state_digest)
        .collect::<Result<Vec<_>, _>>()?;
    let source_digest = adapter_source_digest()?;
    let contract_digest = execution_contract_digest()?;

    let draft = Envelope {
        schema: ENVELOPE_SCHEMA.into(),
        policy: POLICY.into(),
        claim: Claim {
            schema: CLAIM_SCHEMA.into(),
            id: format!("kv.{}", scenario.id),
            statement: "The locally executed KV state sequence equals the expected snapshots supplied in the bound scenario.".into(),
            epistemic_state: EpistemicState::Hypothesis,
            target: Target {
                system: KV_TARGET_SYSTEM.into(),
                revision: source_digest.clone(),
                configuration: scenario_digest.clone(),
                environment: contract_digest.clone(),
            },
            assumptions: vec![
                "Expected snapshots are supplied by the scenario author and are not independently trusted.".into(),
                "The adapter executes only the documented in-process deterministic KV transition contract.".into(),
            ],
            limitations: vec![
                "RECORDED labels identify locally produced adapter output; they do not establish an independent observer, production reachability, or external truth.".into(),
                "The adapter source digest binds rust/src/adapter.rs source text, not the compiled binary, compiler, operating system, or hardware.".into(),
                "Raw observed snapshots are preserved in the adapter receipt; the core envelope contains their domain-separated commitments only.".into(),
            ],
            predicate: TraceEquality {
                kind: PredicateKind::TraceEquality,
                expected: "expected".into(),
                observed: vec!["observed".into()],
                negative_controls: vec!["control".into()],
            },
        },
        evidence: vec![
            EvidenceNode {
                body: EvidenceBody {
                    schema: NODE_SCHEMA.into(),
                    id: "expected".into(),
                    claim_digest: String::new(),
                    parents: vec![],
                    evidence_class: EvidenceClass::Synthetic,
                    producer: Producer {
                        id: "omega-kv-input".into(),
                        kind: ProducerKind::Program,
                    },
                    payload: Payload::StateTrace {
                        states: expected_digests,
                    },
                },
                digest: String::new(),
            },
            EvidenceNode {
                body: EvidenceBody {
                    schema: NODE_SCHEMA.into(),
                    id: "observed".into(),
                    claim_digest: String::new(),
                    parents: vec![],
                    evidence_class: EvidenceClass::Recorded,
                    producer: Producer {
                        id: "omega-kv-adapter".into(),
                        kind: ProducerKind::Program,
                    },
                    payload: Payload::StateTrace {
                        states: observed_digests.clone(),
                    },
                },
                digest: String::new(),
            },
            EvidenceNode {
                body: EvidenceBody {
                    schema: NODE_SCHEMA.into(),
                    id: "control".into(),
                    claim_digest: String::new(),
                    parents: vec!["expected".into(), "observed".into()],
                    evidence_class: EvidenceClass::Synthetic,
                    producer: Producer {
                        id: "omega-kv-adapter".into(),
                        kind: ProducerKind::Program,
                    },
                    payload: Payload::MutationControl {
                        baseline: "observed".into(),
                        index: 0,
                        replacement: mutation_for(&observed_digests[0]),
                    },
                },
                digest: String::new(),
            },
        ],
        digest: String::new(),
    };

    let package = seal(&serde_json::to_vec(&draft).map_err(|e| e.to_string())?)?;
    let snapshots = observed_states
        .into_iter()
        .zip(observed_digests)
        .enumerate()
        .map(|(index, (state, digest))| KvSnapshot {
            index,
            state,
            digest,
        })
        .collect();
    let mut receipt = KvReceipt {
        schema: KV_RECEIPT_SCHEMA.into(),
        scope: KV_RECEIPT_SCOPE.into(),
        scenario_id: scenario.id,
        scenario_digest,
        adapter_source_digest: source_digest,
        execution_contract_digest: contract_digest,
        package_digest: package.digest.clone(),
        snapshots,
        limitations: vec![
            "Receipt integrity is content-addressed but not signed or independently witnessed."
                .into(),
            "Reproducing this receipt does not establish production behavior or external validity."
                .into(),
        ],
        digest: String::new(),
    };
    receipt.digest = receipt_digest(&receipt)?;

    Ok(KvExecution { package, receipt })
}

/// Verifies that a raw KV execution receipt is bound to the exact externally pinned
/// package and to this adapter's documented source/contract boundary. This does not
/// promote runtime, observer, production, or external-validity dimensions.
pub fn verify_kv_receipt(
    package_input: &[u8],
    expected_package_digest: &str,
    receipt_input: &[u8],
) -> Result<KvReceiptBindingReport, String> {
    let core_report = verify(package_input, expected_package_digest)?;
    let package: Envelope =
        serde_json::from_value(encoding::parse(package_input)?).map_err(|e| e.to_string())?;
    let receipt: KvReceipt =
        serde_json::from_value(encoding::parse(receipt_input)?).map_err(|e| e.to_string())?;

    if receipt.schema != KV_RECEIPT_SCHEMA {
        return Err("unsupported KV receipt schema".into());
    }
    if receipt.scope != KV_RECEIPT_SCOPE {
        return Err("unexpected KV receipt scope".into());
    }
    if !valid_identifier(&receipt.scenario_id) {
        return Err("invalid KV receipt scenario id".into());
    }
    if !encoding::is_digest(&receipt.digest) {
        return Err("malformed KV receipt digest".into());
    }
    if receipt.snapshots.is_empty() || receipt.snapshots.len() > MAX_SNAPSHOTS {
        return Err("KV receipt requires 1..257 snapshots".into());
    }
    if package.claim.target.system != KV_TARGET_SYSTEM {
        return Err("package is not bound to the KV target system".into());
    }
    if package.claim.id != format!("kv.{}", receipt.scenario_id) {
        return Err("KV receipt scenario/claim binding mismatch".into());
    }
    if receipt.package_digest != package.digest {
        return Err("KV receipt/package digest binding mismatch".into());
    }
    if receipt.scenario_digest != package.claim.target.configuration {
        return Err("KV receipt scenario/configuration binding mismatch".into());
    }
    if receipt.adapter_source_digest != package.claim.target.revision {
        return Err("KV receipt source/revision binding mismatch".into());
    }
    if receipt.execution_contract_digest != package.claim.target.environment {
        return Err("KV receipt contract/environment binding mismatch".into());
    }
    if receipt.adapter_source_digest != adapter_source_digest()? {
        return Err("KV receipt does not match this adapter source revision".into());
    }
    if receipt.execution_contract_digest != execution_contract_digest()? {
        return Err("KV receipt does not match this execution contract".into());
    }

    if package.claim.predicate.observed.len() != 1 {
        return Err("KV receipt binding requires exactly one observed trace".into());
    }
    let observed_id = package.claim.predicate.observed[0].clone();
    let observed = package
        .evidence
        .iter()
        .find(|node| node.body.id == observed_id)
        .ok_or("KV observed evidence node is missing")?;
    if !matches!(observed.body.evidence_class, EvidenceClass::Recorded)
        || observed.body.producer.id != "omega-kv-adapter"
        || !matches!(observed.body.producer.kind, ProducerKind::Program)
    {
        return Err("KV observed evidence producer boundary mismatch".into());
    }
    let observed_states = match &observed.body.payload {
        Payload::StateTrace { states } => states,
        _ => return Err("KV observed evidence is not a state trace".into()),
    };
    if observed_states.len() != receipt.snapshots.len() {
        return Err("KV receipt snapshot count does not match observed trace".into());
    }

    let mut snapshot_digests = Vec::with_capacity(receipt.snapshots.len());
    for (index, snapshot) in receipt.snapshots.iter().enumerate() {
        if snapshot.index != index {
            return Err(format!("KV receipt snapshot index mismatch at {index}"));
        }
        validate_state(&snapshot.state)?;
        if !encoding::is_digest(&snapshot.digest) {
            return Err(format!("malformed KV snapshot digest at {index}"));
        }
        let recomputed = state_digest(&snapshot.state)?;
        if snapshot.digest != recomputed {
            return Err(format!("KV snapshot digest mismatch at {index}"));
        }
        snapshot_digests.push(recomputed);
    }
    if observed_states != &snapshot_digests {
        return Err("KV raw snapshots do not match the pinned observed trace".into());
    }

    let recomputed_receipt_digest = receipt_digest(&receipt)?;
    if receipt.digest != recomputed_receipt_digest {
        return Err("KV receipt digest mismatch".into());
    }

    Ok(KvReceiptBindingReport {
        schema: KV_RECEIPT_BINDING_SCHEMA.into(),
        status: State::Confirmed,
        scope: KV_BINDING_SCOPE.into(),
        package_digest: package.digest,
        receipt_digest: receipt.digest,
        observed_evidence_id: observed_id,
        snapshot_count: snapshot_digests.len(),
        claim_status: core_report.status,
        limitations: vec![
            "This confirms raw KV snapshot commitments against an externally pinned package; it does not establish independent observation or external truth.".into(),
            "The adapter source identity binds source text embedded in this binary, not compiler, dependency, host, or hardware identity.".into(),
            "A confirmed receipt binding does not promote runtime reproduction, production reachability, consensus/finality, or physical validity.".into(),
        ],
    })
}
