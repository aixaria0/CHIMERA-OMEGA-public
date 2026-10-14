use chimera_omega::{
    adapter::run_kv,
    encoding,
    model::{Overall, State},
    observer::observe_kv,
    witness::{attest_kv_observer, seal_witness_policy, verify_kv_witness},
};
use serde_json::{json, Value};

fn fixture_bytes() -> Vec<u8> {
    include_bytes!("../../examples/adapter/kv-match.json").to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn secret(witness_id: &str, offset: u8) -> Value {
    let bytes = (0..32)
        .map(|index| offset.wrapping_add(index as u8))
        .collect::<Vec<_>>();
    json!({
        "schema": "chimera-witness-secret/v1",
        "scope": "OFFLINE_ED25519_WITNESS_SIGNING_KEY_ONLY",
        "witness_id": witness_id,
        "secret_key": hex(&bytes)
    })
}

fn policy_draft(witness_id: &str, public_key: &str) -> Value {
    json!({
        "schema": "chimera-witness-policy/v1",
        "scope": "EXPLICIT_OFFLINE_WITNESS_AUTHORIZATION_ONLY",
        "authorized_witnesses": [{
            "witness_id": witness_id,
            "public_key": public_key,
            "role": "KV_OBSERVER"
        }],
        "limitations": [
            "Authorization permits policy-local attribution for the KV observer role only; it does not establish truth or independence."
        ],
        "digest": ""
    })
}

fn rehash_attestation(value: &mut Value) {
    let mut body = value.clone();
    body.as_object_mut().unwrap().remove("digest");
    value["digest"] = json!(encoding::digest("witness/attestation/v1", &body).unwrap());
}

fn rehash_policy(value: &mut Value) {
    let mut body = value.clone();
    body.as_object_mut().unwrap().remove("digest");
    value["digest"] = json!(encoding::digest("witness/policy/v1", &body).unwrap());
}

#[test]
fn authorized_signature_confirms_key_binding_and_authorization_not_independence() {
    let execution = run_kv(&fixture_bytes()).unwrap();
    let execution_bytes = serde_json::to_vec(&execution.receipt).unwrap();
    let observer = observe_kv(&execution_bytes).unwrap();
    let secret = secret("witness.alpha", 0);
    let attestation = attest_kv_observer(
        &serde_json::to_vec(&observer).unwrap(),
        &serde_json::to_vec(&secret).unwrap(),
    )
    .unwrap();
    let policy = seal_witness_policy(
        &serde_json::to_vec(&policy_draft(
            &attestation.witness_id,
            &attestation.public_key,
        ))
        .unwrap(),
    )
    .unwrap();

    let report = verify_kv_witness(
        &serde_json::to_vec(&execution.package).unwrap(),
        &execution.package.digest,
        &execution_bytes,
        &serde_json::to_vec(&observer).unwrap(),
        &observer.digest,
        &serde_json::to_vec(&attestation).unwrap(),
        &serde_json::to_vec(&policy).unwrap(),
        &policy.digest,
    )
    .unwrap();

    assert_eq!(report.status, State::Confirmed);
    assert_eq!(report.signature_integrity, State::Confirmed);
    assert_eq!(report.policy_identity_binding, State::Confirmed);
    assert_eq!(report.authorization, State::Confirmed);
    assert_eq!(report.independent_observation, State::Unknown);
}

#[test]
fn valid_digest_with_invalid_signature_is_rejected() {
    let execution = run_kv(&fixture_bytes()).unwrap();
    let execution_bytes = serde_json::to_vec(&execution.receipt).unwrap();
    let observer = observe_kv(&execution_bytes).unwrap();
    let secret = secret("witness.alpha", 0);
    let attestation = attest_kv_observer(
        &serde_json::to_vec(&observer).unwrap(),
        &serde_json::to_vec(&secret).unwrap(),
    )
    .unwrap();
    let policy = seal_witness_policy(
        &serde_json::to_vec(&policy_draft(
            &attestation.witness_id,
            &attestation.public_key,
        ))
        .unwrap(),
    )
    .unwrap();
    let mut forged = serde_json::to_value(&attestation).unwrap();
    forged["signature"] = json!("00".repeat(64));
    rehash_attestation(&mut forged);

    let error = verify_kv_witness(
        &serde_json::to_vec(&execution.package).unwrap(),
        &execution.package.digest,
        &execution_bytes,
        &serde_json::to_vec(&observer).unwrap(),
        &observer.digest,
        &serde_json::to_vec(&forged).unwrap(),
        &serde_json::to_vec(&policy).unwrap(),
        &policy.digest,
    )
    .unwrap_err();
    assert!(error.contains("invalid Ed25519 witness signature"));
}

#[test]
fn cryptographically_valid_but_unauthorized_witness_is_rejected() {
    let execution = run_kv(&fixture_bytes()).unwrap();
    let execution_bytes = serde_json::to_vec(&execution.receipt).unwrap();
    let observer = observe_kv(&execution_bytes).unwrap();
    let authorized = attest_kv_observer(
        &serde_json::to_vec(&observer).unwrap(),
        &serde_json::to_vec(&secret("witness.alpha", 0)).unwrap(),
    )
    .unwrap();
    let unauthorized = attest_kv_observer(
        &serde_json::to_vec(&observer).unwrap(),
        &serde_json::to_vec(&secret("witness.beta", 64)).unwrap(),
    )
    .unwrap();
    let policy = seal_witness_policy(
        &serde_json::to_vec(&policy_draft(
            &authorized.witness_id,
            &authorized.public_key,
        ))
        .unwrap(),
    )
    .unwrap();

    let error = verify_kv_witness(
        &serde_json::to_vec(&execution.package).unwrap(),
        &execution.package.digest,
        &execution_bytes,
        &serde_json::to_vec(&observer).unwrap(),
        &observer.digest,
        &serde_json::to_vec(&unauthorized).unwrap(),
        &serde_json::to_vec(&policy).unwrap(),
        &policy.digest,
    )
    .unwrap_err();
    assert!(error.contains("not authorized by the pinned policy"));
}

#[test]
fn signed_attestation_cannot_be_transplanted_to_another_observer_artifact() {
    let baseline = run_kv(&fixture_bytes()).unwrap();
    let baseline_receipt = serde_json::to_vec(&baseline.receipt).unwrap();
    let baseline_observer = observe_kv(&baseline_receipt).unwrap();
    let secret = secret("witness.alpha", 0);
    let attestation = attest_kv_observer(
        &serde_json::to_vec(&baseline_observer).unwrap(),
        &serde_json::to_vec(&secret).unwrap(),
    )
    .unwrap();
    let policy = seal_witness_policy(
        &serde_json::to_vec(&policy_draft(
            &attestation.witness_id,
            &attestation.public_key,
        ))
        .unwrap(),
    )
    .unwrap();

    let mut scenario: Value = serde_json::from_slice(&fixture_bytes()).unwrap();
    scenario["steps"][0]["delta"] = json!(3);
    scenario["expected"][1]["a"] = json!(4);
    scenario["expected"][2]["a"] = json!(4);
    let changed = run_kv(&serde_json::to_vec(&scenario).unwrap()).unwrap();
    let changed_receipt = serde_json::to_vec(&changed.receipt).unwrap();
    let changed_observer = observe_kv(&changed_receipt).unwrap();

    let error = verify_kv_witness(
        &serde_json::to_vec(&changed.package).unwrap(),
        &changed.package.digest,
        &changed_receipt,
        &serde_json::to_vec(&changed_observer).unwrap(),
        &changed_observer.digest,
        &serde_json::to_vec(&attestation).unwrap(),
        &serde_json::to_vec(&policy).unwrap(),
        &policy.digest,
    )
    .unwrap_err();
    assert!(error.contains("bound to another observer artifact"));
}

#[test]
fn rehashed_policy_mutation_cannot_escape_external_policy_pin() {
    let execution = run_kv(&fixture_bytes()).unwrap();
    let execution_bytes = serde_json::to_vec(&execution.receipt).unwrap();
    let observer = observe_kv(&execution_bytes).unwrap();
    let attestation = attest_kv_observer(
        &serde_json::to_vec(&observer).unwrap(),
        &serde_json::to_vec(&secret("witness.alpha", 0)).unwrap(),
    )
    .unwrap();
    let policy = seal_witness_policy(
        &serde_json::to_vec(&policy_draft(
            &attestation.witness_id,
            &attestation.public_key,
        ))
        .unwrap(),
    )
    .unwrap();
    let original_pin = policy.digest.clone();
    let mut mutated = serde_json::to_value(&policy).unwrap();
    mutated["limitations"][0] = json!("mutated but self-consistently rehashed policy");
    rehash_policy(&mut mutated);

    let error = verify_kv_witness(
        &serde_json::to_vec(&execution.package).unwrap(),
        &execution.package.digest,
        &execution_bytes,
        &serde_json::to_vec(&observer).unwrap(),
        &observer.digest,
        &serde_json::to_vec(&attestation).unwrap(),
        &serde_json::to_vec(&mutated).unwrap(),
        &original_pin,
    )
    .unwrap_err();
    assert!(error.contains("caller witness policy pin mismatch"));
}

#[test]
fn duplicate_policy_identity_fails_closed() {
    let draft = json!({
        "schema": "chimera-witness-policy/v1",
        "scope": "EXPLICIT_OFFLINE_WITNESS_AUTHORIZATION_ONLY",
        "authorized_witnesses": [
            {"witness_id":"witness.alpha","public_key":"11".repeat(32),"role":"KV_OBSERVER"},
            {"witness_id":"witness.alpha","public_key":"22".repeat(32),"role":"KV_OBSERVER"}
        ],
        "limitations": [],
        "digest": ""
    });
    let error = seal_witness_policy(&serde_json::to_vec(&draft).unwrap()).unwrap_err();
    assert!(error.contains("duplicate witness identifier"));
}

#[test]
fn authorized_witness_does_not_turn_a_contradicted_claim_into_truth() {
    let mut scenario: Value = serde_json::from_slice(&fixture_bytes()).unwrap();
    scenario["expected"][1]["a"] = json!(999);
    let execution = run_kv(&serde_json::to_vec(&scenario).unwrap()).unwrap();
    let execution_bytes = serde_json::to_vec(&execution.receipt).unwrap();
    let observer = observe_kv(&execution_bytes).unwrap();
    let attestation = attest_kv_observer(
        &serde_json::to_vec(&observer).unwrap(),
        &serde_json::to_vec(&secret("witness.alpha", 0)).unwrap(),
    )
    .unwrap();
    let policy = seal_witness_policy(
        &serde_json::to_vec(&policy_draft(
            &attestation.witness_id,
            &attestation.public_key,
        ))
        .unwrap(),
    )
    .unwrap();

    let report = verify_kv_witness(
        &serde_json::to_vec(&execution.package).unwrap(),
        &execution.package.digest,
        &execution_bytes,
        &serde_json::to_vec(&observer).unwrap(),
        &observer.digest,
        &serde_json::to_vec(&attestation).unwrap(),
        &serde_json::to_vec(&policy).unwrap(),
        &policy.digest,
    )
    .unwrap();
    assert_eq!(report.status, State::Confirmed);
    assert_eq!(report.claim_status, Overall::Contradicted);
    assert_eq!(report.authorization, State::Confirmed);
    assert_eq!(report.independent_observation, State::Unknown);
}

#[test]
fn separate_witness_process_signs_then_verifier_applies_pinned_authorization() {
    use std::{fs, process::Command};

    let execution = run_kv(&fixture_bytes()).unwrap();
    let execution_bytes = serde_json::to_vec_pretty(&execution.receipt).unwrap();
    let observer = observe_kv(&execution_bytes).unwrap();
    let secret = secret("witness.alpha", 0);
    let direct = attest_kv_observer(
        &serde_json::to_vec(&observer).unwrap(),
        &serde_json::to_vec(&secret).unwrap(),
    )
    .unwrap();
    let draft = policy_draft(&direct.witness_id, &direct.public_key);

    let temp = std::env::temp_dir().join(format!("omega-witness-test-{}", std::process::id()));
    fs::create_dir_all(&temp).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(temp.clone());

    let package_path = temp.join("package.json");
    let execution_path = temp.join("execution.json");
    let observer_path = temp.join("observer.json");
    let secret_path = temp.join("secret.json");
    let attestation_path = temp.join("attestation.json");
    let draft_path = temp.join("policy-draft.json");
    let policy_path = temp.join("policy.json");
    fs::write(
        &package_path,
        serde_json::to_vec_pretty(&execution.package).unwrap(),
    )
    .unwrap();
    fs::write(&execution_path, &execution_bytes).unwrap();
    fs::write(
        &observer_path,
        serde_json::to_vec_pretty(&observer).unwrap(),
    )
    .unwrap();
    fs::write(&secret_path, serde_json::to_vec_pretty(&secret).unwrap()).unwrap();
    fs::write(&draft_path, serde_json::to_vec_pretty(&draft).unwrap()).unwrap();

    let signed = Command::new(env!("CARGO_BIN_EXE_omega-witness"))
        .args([
            "attest-kv-observer",
            observer_path.to_str().unwrap(),
            "--key",
            secret_path.to_str().unwrap(),
            "--out",
            attestation_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(signed.status.code(), Some(0));
    let signed_result: Value = serde_json::from_slice(&signed.stdout).unwrap();
    assert_eq!(signed_result["status"], json!("SIGNED_NOT_AUTHORIZED"));

    let sealed = Command::new(env!("CARGO_BIN_EXE_omega"))
        .args(["seal-witness-policy", draft_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(sealed.status.code(), Some(0));
    let policy: Value = serde_json::from_slice(&sealed.stdout).unwrap();
    fs::write(&policy_path, serde_json::to_vec_pretty(&policy).unwrap()).unwrap();

    let attestation: Value = serde_json::from_slice(&fs::read(&attestation_path).unwrap()).unwrap();
    assert_eq!(attestation["digest"], json!(direct.digest));

    let verified = Command::new(env!("CARGO_BIN_EXE_omega"))
        .args([
            "verify-kv-witness",
            package_path.to_str().unwrap(),
            "--expect",
            &execution.package.digest,
            "--receipt",
            execution_path.to_str().unwrap(),
            "--observer",
            observer_path.to_str().unwrap(),
            "--expect-observer",
            &observer.digest,
            "--attestation",
            attestation_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--expect-policy",
            policy["digest"].as_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(verified.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(report["signature_integrity"], json!("CONFIRMED"));
    assert_eq!(report["policy_identity_binding"], json!("CONFIRMED"));
    assert_eq!(report["authorization"], json!("CONFIRMED"));
    assert_eq!(report["independent_observation"], json!("UNKNOWN"));
}
