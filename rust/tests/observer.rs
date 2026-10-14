use chimera_omega::{
    adapter::run_kv,
    encoding,
    model::{Overall, State},
    observer::{observe_kv, verify_kv_observer},
};
use serde_json::{json, Value};

fn fixture_bytes() -> Vec<u8> {
    include_bytes!("../../examples/adapter/kv-match.json").to_vec()
}

fn fixture_value() -> Value {
    serde_json::from_slice(&fixture_bytes()).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn rehash_execution_receipt(receipt: &mut Value) {
    let mut body = receipt.clone();
    body.as_object_mut().unwrap().remove("digest");
    receipt["digest"] = json!(encoding::digest("adapter/kv-receipt/v1", &body).unwrap());
}

fn rehash_observer_receipt(receipt: &mut Value) {
    let observation = json!({
        "execution_receipt_digest": receipt["execution_receipt_digest"],
        "observed_commitments": receipt["observed_commitments"]
    });
    receipt["observation_digest"] =
        json!(encoding::digest("observer/kv-observation/v1", &observation).unwrap());
    let mut body = receipt.clone();
    body.as_object_mut().unwrap().remove("digest");
    receipt["digest"] = json!(encoding::digest("observer/kv-receipt/v1", &body).unwrap());
}

#[test]
fn observer_recomputes_raw_execution_artifact_without_claim_authority() {
    let execution = run_kv(&fixture_bytes()).unwrap();
    let observer = observe_kv(&serde_json::to_vec(&execution.receipt).unwrap()).unwrap();

    assert_eq!(observer.execution_receipt_digest, execution.receipt.digest);
    assert_eq!(observer.snapshot_count, execution.receipt.snapshots.len());
    assert_eq!(
        observer.observed_commitments,
        execution
            .receipt
            .snapshots
            .iter()
            .map(|snapshot| snapshot.digest.clone())
            .collect::<Vec<_>>()
    );
    assert!(observer
        .limitations
        .iter()
        .any(|item| item.contains("cannot promote the independent_observation")));
}

#[test]
fn observer_rejects_stale_tampering_before_authoring_observation() {
    let execution = run_kv(&fixture_bytes()).unwrap();
    let mut receipt = serde_json::to_value(&execution.receipt).unwrap();
    receipt["snapshots"][0]["state"]["a"] = json!(99);

    let error = observe_kv(&bytes(&receipt)).unwrap_err();
    assert!(error.contains("execution receipt digest mismatch"));
}

#[test]
fn observer_binding_confirms_artifact_chain_without_promoting_independence() {
    let execution = run_kv(&fixture_bytes()).unwrap();
    let execution_bytes = serde_json::to_vec(&execution.receipt).unwrap();
    let observer = observe_kv(&execution_bytes).unwrap();
    let report = verify_kv_observer(
        &serde_json::to_vec(&execution.package).unwrap(),
        &execution.package.digest,
        &execution_bytes,
        &serde_json::to_vec(&observer).unwrap(),
        &observer.digest,
    )
    .unwrap();

    assert_eq!(report.status, State::Confirmed);
    assert_eq!(report.claim_status, Overall::LocallySupported);
    assert_eq!(report.independent_observation, State::Unknown);
    assert_eq!(report.snapshot_count, execution.receipt.snapshots.len());
    assert!(report
        .limitations
        .iter()
        .any(|item| item.contains("remains UNKNOWN")));
}

#[test]
fn fully_rehashed_forged_observer_receipt_fails_deterministic_recomputation() {
    let execution = run_kv(&fixture_bytes()).unwrap();
    let execution_bytes = serde_json::to_vec(&execution.receipt).unwrap();
    let observer = observe_kv(&execution_bytes).unwrap();
    let mut forged = serde_json::to_value(&observer).unwrap();
    forged["observed_commitments"][0] = json!("f".repeat(64));
    rehash_observer_receipt(&mut forged);
    let forged_pin = forged["digest"].as_str().unwrap().to_string();

    let error = verify_kv_observer(
        &serde_json::to_vec(&execution.package).unwrap(),
        &execution.package.digest,
        &execution_bytes,
        &bytes(&forged),
        &forged_pin,
    )
    .unwrap_err();
    assert!(error.contains("does not match deterministic recomputation"));
}

#[test]
fn observer_from_another_execution_cannot_be_transplanted() {
    let baseline = run_kv(&fixture_bytes()).unwrap();
    let baseline_receipt = serde_json::to_vec(&baseline.receipt).unwrap();

    let mut scenario = fixture_value();
    scenario["steps"][0]["delta"] = json!(3);
    scenario["expected"][1]["a"] = json!(4);
    scenario["expected"][2]["a"] = json!(4);
    let changed = run_kv(&bytes(&scenario)).unwrap();
    let changed_observer = observe_kv(&serde_json::to_vec(&changed.receipt).unwrap()).unwrap();

    let error = verify_kv_observer(
        &serde_json::to_vec(&baseline.package).unwrap(),
        &baseline.package.digest,
        &baseline_receipt,
        &serde_json::to_vec(&changed_observer).unwrap(),
        &changed_observer.digest,
    )
    .unwrap_err();
    assert!(error.contains("observer/execution receipt binding mismatch"));
}

#[test]
fn fully_rehashed_execution_tampering_is_still_stopped_by_pinned_package() {
    let execution = run_kv(&fixture_bytes()).unwrap();
    let mut receipt = serde_json::to_value(&execution.receipt).unwrap();
    receipt["snapshots"][0]["state"]["a"] = json!(99);
    receipt["snapshots"][0]["digest"] =
        json!(encoding::digest("adapter/kv-state/v1", &receipt["snapshots"][0]["state"]).unwrap());
    rehash_execution_receipt(&mut receipt);
    let observer = observe_kv(&bytes(&receipt)).unwrap();

    let error = verify_kv_observer(
        &serde_json::to_vec(&execution.package).unwrap(),
        &execution.package.digest,
        &bytes(&receipt),
        &serde_json::to_vec(&observer).unwrap(),
        &observer.digest,
    )
    .unwrap_err();
    assert!(error.contains("raw snapshots do not match the pinned observed trace"));
}

#[test]
fn separate_observer_process_is_deterministic_and_verifier_keeps_authority_bounded() {
    use std::{fs, process::Command};

    let execution = run_kv(&fixture_bytes()).unwrap();
    let temp = std::env::temp_dir().join(format!("omega-observer-test-{}", std::process::id()));
    fs::create_dir_all(&temp).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(temp.clone());

    let package = temp.join("package.json");
    let execution_receipt = temp.join("execution-receipt.json");
    let observer_one = temp.join("observer-one.json");
    let observer_two = temp.join("observer-two.json");
    fs::write(
        &package,
        serde_json::to_vec_pretty(&execution.package).unwrap(),
    )
    .unwrap();
    fs::write(
        &execution_receipt,
        serde_json::to_vec_pretty(&execution.receipt).unwrap(),
    )
    .unwrap();

    for output in [&observer_one, &observer_two] {
        let observed = Command::new(env!("CARGO_BIN_EXE_omega-observer"))
            .args([
                "observe-kv",
                execution_receipt.to_str().unwrap(),
                "--out",
                output.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(observed.status.code(), Some(0));
        let result: Value = serde_json::from_slice(&observed.stdout).unwrap();
        assert_eq!(result["status"], json!("OBSERVED_NOT_AUTHORIZED"));
    }

    assert_eq!(
        fs::read(&observer_one).unwrap(),
        fs::read(&observer_two).unwrap()
    );
    let observer: Value = serde_json::from_slice(&fs::read(&observer_one).unwrap()).unwrap();
    let observer_pin = observer["digest"].as_str().unwrap();

    let verified = Command::new(env!("CARGO_BIN_EXE_omega"))
        .args([
            "verify-kv-observer",
            package.to_str().unwrap(),
            "--expect",
            &execution.package.digest,
            "--receipt",
            execution_receipt.to_str().unwrap(),
            "--observer",
            observer_one.to_str().unwrap(),
            "--expect-observer",
            observer_pin,
        ])
        .output()
        .unwrap();
    assert_eq!(verified.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(report["status"], json!("CONFIRMED"));
    assert_eq!(report["independent_observation"], json!("UNKNOWN"));
    assert_eq!(
        report["scope"],
        json!("KV_OBSERVER_ARTIFACT_TO_PINNED_PACKAGE_BINDING_ONLY")
    );
}
