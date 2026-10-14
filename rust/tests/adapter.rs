use chimera_omega::{
    adapter::{run_kv, verify_kv_receipt},
    encoding,
    model::{Overall, State},
    verify,
};
use serde_json::{json, Value};

fn fixture_bytes() -> Vec<u8> {
    include_bytes!("../../examples/adapter/kv-match.json").to_vec()
}

fn fixture_value() -> Value {
    serde_json::from_slice(&fixture_bytes()).unwrap()
}

fn rehash_receipt(receipt: &mut Value) {
    let mut body = receipt.clone();
    body.as_object_mut().unwrap().remove("digest");
    receipt["digest"] = json!(encoding::digest("adapter/kv-receipt/v1", &body).unwrap());
}

#[test]
fn adapter_executes_raw_states_and_authors_existing_v2_package() {
    let execution = run_kv(&fixture_bytes()).unwrap();

    assert_eq!(
        execution.package.claim.target.configuration,
        execution.receipt.scenario_digest
    );
    assert_eq!(
        execution.package.claim.target.revision,
        execution.receipt.adapter_source_digest
    );
    assert_eq!(
        execution.package.claim.target.environment,
        execution.receipt.execution_contract_digest
    );
    assert_eq!(execution.receipt.package_digest, execution.package.digest);
    assert_eq!(execution.receipt.snapshots.len(), 4);

    for snapshot in &execution.receipt.snapshots {
        let digest = encoding::digest(
            "adapter/kv-state/v1",
            &serde_json::to_value(&snapshot.state).unwrap(),
        )
        .unwrap();
        assert_eq!(snapshot.digest, digest);
    }

    let report = verify(
        &serde_json::to_vec(&execution.package).unwrap(),
        &execution.package.digest,
    )
    .unwrap();
    assert_eq!(report.status, Overall::LocallySupported);
    assert_eq!(report.dimensions.artifact_conformance, State::Confirmed);
    assert_eq!(report.dimensions.negative_control, State::Pass);
    assert_eq!(report.dimensions.runtime_reproduction, State::Unknown);
    assert_eq!(report.dimensions.independent_observation, State::Unknown);
    assert_eq!(report.dimensions.production_reachability, State::Unknown);
}

#[test]
fn adapter_output_is_deterministic() {
    let first = serde_json::to_value(run_kv(&fixture_bytes()).unwrap()).unwrap();
    let second = serde_json::to_value(run_kv(&fixture_bytes()).unwrap()).unwrap();
    assert_eq!(first, second);
}

#[test]
fn tampered_adapter_package_is_rejected_before_verdict() {
    let execution = run_kv(&fixture_bytes()).unwrap();
    let pin = execution.package.digest.clone();
    let mut package = serde_json::to_value(&execution.package).unwrap();
    let observed = package["evidence"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|node| node["body"]["id"] == "observed")
        .unwrap();
    observed["body"]["payload"]["states"][0] = json!("f".repeat(64));

    let error = verify(&serde_json::to_vec(&package).unwrap(), &pin).unwrap_err();
    assert!(error.contains("evidence digest mismatch"));
}

#[test]
fn contradictory_expected_snapshot_is_preserved_not_hidden() {
    let mut scenario = fixture_value();
    scenario["expected"][2]["b"] = json!(9);
    let execution = run_kv(&serde_json::to_vec(&scenario).unwrap()).unwrap();
    let report = verify(
        &serde_json::to_vec(&execution.package).unwrap(),
        &execution.package.digest,
    )
    .unwrap();
    assert_eq!(report.status, Overall::Contradicted);
    assert_eq!(report.comparisons[0].state, State::Contradicted);
    assert_eq!(
        report.comparisons[0]
            .first_divergence
            .as_ref()
            .unwrap()
            .index,
        2
    );
}

#[test]
fn scenario_mutation_changes_bound_configuration_and_package_identity() {
    let baseline = run_kv(&fixture_bytes()).unwrap();
    let mut scenario = fixture_value();
    scenario["steps"][0]["delta"] = json!(3);
    scenario["expected"][1]["a"] = json!(4);
    scenario["expected"][2]["a"] = json!(4);
    let changed = run_kv(&serde_json::to_vec(&scenario).unwrap()).unwrap();
    assert_ne!(
        baseline.receipt.scenario_digest,
        changed.receipt.scenario_digest
    );
    assert_ne!(baseline.package.digest, changed.package.digest);
}

#[test]
fn invalid_transition_inputs_fail_closed() {
    let mut scenario = fixture_value();
    scenario["steps"][0]["key"] = json!("missing");
    assert!(run_kv(&serde_json::to_vec(&scenario).unwrap())
        .unwrap_err()
        .contains("absent key"));

    let mut scenario = fixture_value();
    scenario["expected"].as_array_mut().unwrap().pop();
    assert!(run_kv(&serde_json::to_vec(&scenario).unwrap())
        .unwrap_err()
        .contains("expected snapshots"));

    let mut scenario = fixture_value();
    scenario["initial"]["a"] = json!(9_007_199_254_740_991_u64);
    scenario["steps"][0]["delta"] = json!(1);
    assert!(run_kv(&serde_json::to_vec(&scenario).unwrap())
        .unwrap_err()
        .contains("safe integer range"));

    let mut scenario = fixture_value();
    scenario["initial"] = json!({"é": 1});
    assert!(run_kv(&serde_json::to_vec(&scenario).unwrap()).is_err());
}

#[test]
fn receipt_is_content_addressed_but_not_authority() {
    let execution = run_kv(&fixture_bytes()).unwrap();
    let mut value = serde_json::to_value(&execution.receipt).unwrap();
    let recorded = value["digest"].as_str().unwrap().to_string();
    value.as_object_mut().unwrap().remove("digest");
    let recomputed = encoding::digest("adapter/kv-receipt/v1", &value).unwrap();
    assert_eq!(recorded, recomputed);
    assert!(execution
        .receipt
        .limitations
        .iter()
        .any(|item| item.contains("not signed")));
}

#[test]
fn receipt_binding_confirms_raw_snapshots_without_promoting_authority() {
    let execution = run_kv(&fixture_bytes()).unwrap();
    let report = verify_kv_receipt(
        &serde_json::to_vec(&execution.package).unwrap(),
        &execution.package.digest,
        &serde_json::to_vec(&execution.receipt).unwrap(),
    )
    .unwrap();

    assert_eq!(report.status, State::Confirmed);
    assert_eq!(report.claim_status, Overall::LocallySupported);
    assert_eq!(report.snapshot_count, execution.receipt.snapshots.len());
    assert_eq!(report.observed_evidence_id, "observed");
    assert!(report
        .limitations
        .iter()
        .any(|item| item.contains("does not establish independent observation")));
}

#[test]
fn receipt_binding_rejects_raw_state_mutation() {
    let execution = run_kv(&fixture_bytes()).unwrap();
    let mut receipt = serde_json::to_value(&execution.receipt).unwrap();
    receipt["snapshots"][0]["state"]["a"] = json!(99);

    let error = verify_kv_receipt(
        &serde_json::to_vec(&execution.package).unwrap(),
        &execution.package.digest,
        &serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap_err();
    assert!(error.contains("snapshot digest mismatch"));
}

#[test]
fn self_consistent_receipt_rehash_cannot_escape_pinned_observed_trace() {
    let execution = run_kv(&fixture_bytes()).unwrap();
    let mut receipt = serde_json::to_value(&execution.receipt).unwrap();
    receipt["snapshots"][0]["state"]["a"] = json!(99);
    receipt["snapshots"][0]["digest"] =
        json!(encoding::digest("adapter/kv-state/v1", &receipt["snapshots"][0]["state"]).unwrap());
    rehash_receipt(&mut receipt);

    let error = verify_kv_receipt(
        &serde_json::to_vec(&execution.package).unwrap(),
        &execution.package.digest,
        &serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap_err();
    assert!(error.contains("raw snapshots do not match the pinned observed trace"));
}

#[test]
fn receipt_from_another_package_cannot_be_transplanted() {
    let baseline = run_kv(&fixture_bytes()).unwrap();
    let mut scenario = fixture_value();
    scenario["steps"][0]["delta"] = json!(3);
    scenario["expected"][1]["a"] = json!(4);
    scenario["expected"][2]["a"] = json!(4);
    let changed = run_kv(&serde_json::to_vec(&scenario).unwrap()).unwrap();

    let error = verify_kv_receipt(
        &serde_json::to_vec(&baseline.package).unwrap(),
        &baseline.package.digest,
        &serde_json::to_vec(&changed.receipt).unwrap(),
    )
    .unwrap_err();
    assert!(error.contains("receipt/package digest binding mismatch"));
}

#[test]
fn cli_runs_adapter_then_core_verifier_without_promoting_runtime_authority() {
    use std::{fs, process::Command};

    let temp = std::env::temp_dir().join(format!("omega-kv-cli-test-{}", std::process::id()));
    fs::create_dir_all(&temp).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(temp.clone());

    let scenario = temp.join("scenario.json");
    let package = temp.join("package.json");
    let receipt = temp.join("receipt.json");
    fs::write(&scenario, fixture_bytes()).unwrap();

    let run = Command::new(env!("CARGO_BIN_EXE_omega"))
        .args([
            "run-kv",
            scenario.to_str().unwrap(),
            "--package",
            package.to_str().unwrap(),
            "--receipt",
            receipt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(0));
    let authored: Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(authored["status"], json!("AUTHORED_NOT_VERIFIED"));
    assert!(package.exists());
    assert!(receipt.exists());

    let pin = authored["package_digest"].as_str().unwrap();
    let verified = Command::new(env!("CARGO_BIN_EXE_omega"))
        .args(["verify", package.to_str().unwrap(), "--expect", pin])
        .output()
        .unwrap();
    assert_eq!(verified.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(report["status"], json!("LOCALLY_SUPPORTED"));
    assert_eq!(
        report["dimensions"]["runtime_reproduction"],
        json!("UNKNOWN")
    );
    assert_eq!(
        report["dimensions"]["independent_observation"],
        json!("UNKNOWN")
    );

    let bound = Command::new(env!("CARGO_BIN_EXE_omega"))
        .args([
            "verify-kv-receipt",
            package.to_str().unwrap(),
            "--expect",
            pin,
            "--receipt",
            receipt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(bound.status.code(), Some(0));
    let binding: Value = serde_json::from_slice(&bound.stdout).unwrap();
    assert_eq!(binding["status"], json!("CONFIRMED"));
    assert_eq!(
        binding["scope"],
        json!("KV_RAW_SNAPSHOT_TO_PINNED_PACKAGE_BINDING_ONLY")
    );
    assert_eq!(binding["claim_status"], json!("LOCALLY_SUPPORTED"));
    assert!(binding.get("dimensions").is_none());

    let mut tampered: Value = serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    tampered["snapshots"][0]["state"]["a"] = json!(99);
    fs::write(&receipt, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_omega"))
        .args([
            "verify-kv-receipt",
            package.to_str().unwrap(),
            "--expect",
            pin,
            "--receipt",
            receipt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&rejected.stdout).unwrap()["status"],
        json!("REJECTED")
    );
}
