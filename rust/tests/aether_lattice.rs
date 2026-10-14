use chimera_omega::{
    aether_lattice::{verify_aether_lineage, CERTIFICATE_DOMAIN, CONTEXT_DOMAIN},
    encoding,
    model::State,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, process::Command};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/aether-lineage/");
const BODY_FIELDS: [&str; 16] = [
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

fn file(name: &str, suffix: &str) -> Vec<u8> {
    fs::read(format!("{ROOT}{name}.{suffix}")).unwrap()
}

fn fixture(name: &str) -> (Value, Value) {
    (
        serde_json::from_slice(&file(name, "evidence.json")).unwrap(),
        serde_json::from_slice(&file(name, "context.json")).unwrap(),
    )
}

fn pin_context(context: &Value) -> String {
    encoding::digest(CONTEXT_DOMAIN, context).unwrap()
}

fn refresh_pin(bundle: &Value, context: &mut Value) {
    context["certificate_digest"] =
        json!(encoding::digest(CERTIFICATE_DOMAIN, &bundle["certificate"]).unwrap());
}

fn check(bundle: &Value, context: &Value) -> Result<Value, String> {
    let result = verify_aether_lineage(
        &serde_json::to_vec(bundle).unwrap(),
        &serde_json::to_vec(context).unwrap(),
        &pin_context(context),
    )?;
    Ok(serde_json::to_value(result).unwrap())
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Test-only signing seed. This never reads the recorded producer's private key.
fn sign_record(record: &mut Value, key: &SigningKey) {
    let mut receipt = record["receipt"].clone();
    for name in ["task_id", "parent_task_id", "operation"] {
        receipt[name] = record[name].clone();
    }
    receipt["input_sha256"] = json!(hash(record["payload"].as_str().unwrap().as_bytes()));
    receipt["output_sha256"] = json!(hash(record["output"].as_str().unwrap().as_bytes()));
    let descriptor = format!(
        "aether-policy-v{}|operation={}|capabilities={}|max-input=65536|max-output=65536|deadline-ms={}|executor={}",
        receipt["policy_revision"].as_u64().unwrap(), receipt["operation"].as_str().unwrap(),
        receipt["capabilities"].as_u64().unwrap(), receipt["deadline_ms"].as_u64().unwrap(),
        receipt["executor_id"].as_str().unwrap(),
    );
    receipt["policy_sha256"] = json!(hash(descriptor.as_bytes()));
    receipt["executor_identity_sha256"] =
        json!(hash(receipt["executor_id"].as_str().unwrap().as_bytes()));
    let pairs: Vec<_> = BODY_FIELDS
        .iter()
        .map(|name| {
            format!(
                "{}:{}",
                serde_json::to_string(name).unwrap(),
                serde_json::to_string(&receipt[*name]).unwrap()
            )
        })
        .collect();
    let digest = hash(format!("{{{}}}", pairs.join(",")).as_bytes());
    receipt["receipt_sha256"] = json!(digest);
    let domain = "aether.execution-receipt.v1";
    let mut message = (domain.len() as u64).to_be_bytes().to_vec();
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(digest.as_bytes());
    let signature = key.sign(&message);
    // Keep an explicit crypto control before asking the semantic verifier to reject.
    key.verifying_key()
        .verify_strict(&message, &signature)
        .unwrap();
    receipt["attestation"] = json!({
        "algorithm": "ed25519", "domain": domain,
        "public_key_hex": hex(&key.verifying_key().to_bytes()),
        "key_fingerprint_sha256": hash(&key.verifying_key().to_bytes()),
        "signature_hex": hex(&signature.to_bytes()),
    });
    record["receipt"] = receipt;
}

fn signed_projection(bundle: &mut Value, context: &mut Value, key: &SigningKey) {
    sign_record(&mut bundle["execution"], key);
    if !bundle["parent"].is_null() {
        sign_record(&mut bundle["parent"], key);
    }
    let record = bundle["execution"].clone();
    let receipt = &record["receipt"];
    let task = record["task_id"].as_str().unwrap();
    let input = format!("aether:artifact:{task}:input");
    let output = format!("aether:artifact:{task}:output");
    bundle["certificate"]["artifacts"] = json!([
        {"id": input, "kind": "execution_input", "sha256": receipt["input_sha256"], "parent": null},
        {"id": output, "kind": "execution_output", "sha256": receipt["output_sha256"], "parent": input},
    ]);
    bundle["certificate"]["transformation"] = json!({
        "id": format!("aether:transformation:{task}"), "operation": record["operation"],
        "input": input, "output": output, "evidence_ref": receipt["receipt_sha256"],
        "replay_of": record["parent_task_id"].as_str().map(|id| format!("aether:transformation:{id}")),
    });
    bundle["certificate"]["evidence"]["receipt"] = receipt.clone();
    bundle["certificate"]["evidence"]["source"] = json!(format!("/evidence/{task}"));
    let fingerprint = hash(&key.verifying_key().to_bytes());
    bundle["certificate"]["assessment"]["trusted_signer_fingerprint_sha256"] = json!(fingerprint);
    context["trusted_signer_fingerprint_sha256"] = json!(fingerprint);
    refresh_pin(bundle, context);
}

#[test]
fn real_aether_exports_bind_without_promoting_unknown_dimensions() {
    for name in ["echo", "uppercase", "sha256", "empty", "replay"] {
        let pin = String::from_utf8(file(name, "context.sha256")).unwrap();
        let report = verify_aether_lineage(
            &file(name, "evidence.json"),
            &file(name, "context.json"),
            pin.trim(),
        )
        .unwrap();
        assert_eq!(report.signature_integrity, State::Confirmed);
        assert_eq!(report.journal_checkpoint_binding, State::Confirmed);
        assert_eq!(report.journal_chain_integrity, State::Unknown);
        assert_eq!(report.independent_observation, State::Unknown);
        assert_eq!(report.producer_binary_attestation, State::Unknown);
        assert_eq!(report.omega_core_verdict, State::NotRun);
        assert_eq!(report.runtime_reproduction, State::NotRun);
        assert_eq!(
            report.direct_replay_binding,
            if name == "replay" {
                State::Confirmed
            } else {
                State::NotApplicable
            }
        );
    }
}

#[test]
fn external_context_pin_rejects_whole_context_replacement() {
    let (bundle, mut context) = fixture("echo");
    let pin = pin_context(&context);
    context["trusted_signer_fingerprint_sha256"] = json!("0".repeat(64));
    let error = verify_aether_lineage(
        &serde_json::to_vec(&bundle).unwrap(),
        &serde_json::to_vec(&context).unwrap(),
        &pin,
    )
    .err()
    .unwrap();
    assert!(error.contains("context digest mismatch"), "{error}");
}

#[test]
fn repinning_cannot_bypass_source_identity_or_checkpoint_constraints() {
    for (field, replacement) in [
        ("source_repository", json!("aixaria0/Aether-Runtime-OS")),
        ("source_revision", json!("f".repeat(40))),
        ("trusted_signer_fingerprint_sha256", json!("0".repeat(64))),
        ("journal_head_sha256", json!("0".repeat(64))),
        ("journal_event_count", json!(999)),
    ] {
        let (bundle, mut context) = fixture("echo");
        context[field] = replacement;
        assert!(check(&bundle, &context).is_err(), "{field}");
    }
}

#[test]
fn raw_byte_mutations_fail_even_with_accepted_producer_flags() {
    for field in ["payload", "output", "task_id", "operation"] {
        let (mut bundle, context) = fixture("echo");
        bundle["execution"][field] = json!("changed");
        assert_eq!(bundle["certificate"]["assessment"]["status"], "accepted");
        assert!(check(&bundle, &context).is_err(), "{field}");
    }
}

#[test]
fn freshly_repinned_graph_and_receipt_transplants_are_rejected() {
    for path in [
        vec!["artifacts", "0", "id"],
        vec!["artifacts", "1", "parent"],
        vec!["artifacts", "1", "sha256"],
        vec!["transformation", "input"],
        vec!["transformation", "output"],
        vec!["transformation", "evidence_ref"],
        vec!["transformation", "operation"],
        vec!["evidence", "source"],
    ] {
        let (mut bundle, mut context) = fixture("echo");
        let mut cursor = &mut bundle["certificate"];
        for part in &path[..path.len() - 1] {
            cursor = if let Ok(index) = part.parse::<usize>() {
                &mut cursor[index]
            } else {
                &mut cursor[*part]
            };
        }
        cursor[*path.last().unwrap()] = json!("changed");
        refresh_pin(&bundle, &mut context);
        assert!(check(&bundle, &context).is_err(), "{path:?}");
    }
    let (mut bundle, mut context) = fixture("echo");
    let (other, _) = fixture("uppercase");
    bundle["certificate"]["evidence"]["receipt"] = other["execution"]["receipt"].clone();
    refresh_pin(&bundle, &mut context);
    assert!(check(&bundle, &context).is_err());
}

#[test]
fn forged_attestation_fields_fail_after_certificate_repinning() {
    for (field, replacement) in [
        ("signature_hex", "0".repeat(128)),
        ("public_key_hex", "0".repeat(64)),
        ("key_fingerprint_sha256", "0".repeat(64)),
        ("algorithm", "none".into()),
        ("domain", "another.domain".into()),
    ] {
        let (mut bundle, mut context) = fixture("echo");
        bundle["execution"]["receipt"]["attestation"][field] = json!(replacement);
        bundle["certificate"]["evidence"]["receipt"] = bundle["execution"]["receipt"].clone();
        refresh_pin(&bundle, &mut context);
        assert!(check(&bundle, &context).is_err(), "{field}");
    }
}

#[test]
fn valid_signature_on_wrong_operation_result_is_rejected() {
    let (mut bundle, mut context) = fixture("echo");
    bundle["execution"]["output"] = json!("wrong but authentically signed");
    signed_projection(&mut bundle, &mut context, &SigningKey::from_bytes(&[7; 32]));
    assert_eq!(bundle["certificate"]["assessment"]["status"], "accepted");
    let error = check(&bundle, &context).unwrap_err();
    assert!(error.contains("operation result mismatch"), "{error}");
}

#[test]
fn valid_signed_capability_and_policy_escalations_are_rejected() {
    for (field, replacement) in [
        ("capabilities", json!(9)),
        ("capability_names", json!(["compute", "network"])),
        ("policy_revision", json!(2)),
        ("deadline_ms", json!(0)),
        ("deadline_ms", json!(10001)),
        ("executor_id", json!("unreviewed-executor")),
        ("verified", json!(false)),
        ("receipt_version", json!(1)),
        ("permit_id", json!("not-a-uuid")),
    ] {
        let (mut bundle, mut context) = fixture("echo");
        bundle["execution"]["receipt"][field] = replacement;
        signed_projection(&mut bundle, &mut context, &SigningKey::from_bytes(&[7; 32]));
        assert!(check(&bundle, &context).is_err(), "{field}");
    }
}

#[test]
fn a_valid_self_selected_signer_does_not_replace_the_context_authority() {
    let (mut bundle, mut context) = fixture("echo");
    let trusted = context["trusted_signer_fingerprint_sha256"].clone();
    signed_projection(&mut bundle, &mut context, &SigningKey::from_bytes(&[8; 32]));
    context["trusted_signer_fingerprint_sha256"] = trusted;
    let error = check(&bundle, &context).unwrap_err();
    assert!(error.contains("not trusted"), "{error}");
}

#[test]
fn replay_requires_the_authentic_matching_direct_parent() {
    let (mut bundle, context) = fixture("replay");
    bundle["parent"] = Value::Null;
    assert!(check(&bundle, &context).is_err());
    let (mut bundle, mut context) = fixture("replay");
    bundle["parent"]["payload"] = json!("a different authentic input");
    bundle["parent"]["output"] = json!("a different authentic input");
    signed_projection(&mut bundle, &mut context, &SigningKey::from_bytes(&[7; 32]));
    let error = check(&bundle, &context).unwrap_err();
    assert!(error.contains("direct replay parent"), "{error}");
    let (mut bundle, context) = fixture("echo");
    bundle["parent"] = fixture("uppercase").0["execution"].clone();
    assert!(check(&bundle, &context).is_err());
}

#[test]
fn producer_journal_rejection_stays_attributed_and_chain_integrity_unknown() {
    let (mut bundle, mut context) = fixture("echo");
    bundle["certificate"]["evidence"]["journal"]["valid"] = json!(false);
    bundle["certificate"]["evidence"]["journal"]["first_invalid_sequence"] = json!(1);
    bundle["certificate"]["invariants"][6]["passed"] = json!(false);
    bundle["certificate"]["assessment"]["status"] = json!("rejected");
    bundle["certificate"]["assessment"]["failed_invariants"] = json!(["journal_integrity"]);
    refresh_pin(&bundle, &mut context);
    let report = check(&bundle, &context).unwrap();
    assert_eq!(report["status"], "CONFIRMED");
    assert_eq!(report["producer_assessment"], "rejected");
    assert_eq!(report["producer_journal_valid"], false);
    assert_eq!(report["journal_chain_integrity"], "UNKNOWN");
    assert_eq!(report["omega_core_verdict"], "NOT_RUN");
}

#[test]
fn malformed_assessments_duplicate_keys_and_large_inputs_fail_closed() {
    let (mut bundle, mut context) = fixture("echo");
    bundle["certificate"]["invariants"][0]["passed"] = json!(false);
    refresh_pin(&bundle, &mut context);
    assert!(check(&bundle, &context).is_err());
    let duplicate = br#"{"schema":"a","schema":"b"}"#;
    assert!(verify_aether_lineage(
        duplicate,
        &file("echo", "context.json"),
        String::from_utf8(file("echo", "context.sha256"))
            .unwrap()
            .trim()
    )
    .is_err());
    let (mut bundle, context) = fixture("echo");
    bundle["execution"]["payload"] = json!("x".repeat(4097));
    assert!(check(&bundle, &context).is_err());
    assert!(verify_aether_lineage(
        &vec![b' '; encoding::MAX_BYTES + 1],
        &file("echo", "context.json"),
        &pin_context(&context)
    )
    .is_err());
}

#[test]
fn separate_cli_process_reproduces_all_recorded_binding_reports() {
    for name in ["echo", "uppercase", "sha256", "empty", "replay"] {
        let pin = String::from_utf8(file(name, "context.sha256")).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_omega"))
            .args([
                "verify-aether-lineage",
                &format!("{ROOT}{name}.evidence.json"),
                "--context",
                &format!("{ROOT}{name}.context.json"),
                "--expect-context",
                pin.trim(),
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
        let recorded: Value = serde_json::from_slice(&file(name, "report.json")).unwrap();
        assert_eq!(actual, recorded);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_omega"))
        .args([
            "verify-aether-lineage",
            &format!("{ROOT}echo.evidence.json"),
            "--context",
            &format!("{ROOT}echo.context.json"),
            "--expect-context",
            &"0".repeat(64),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["status"],
        "REJECTED"
    );
}
