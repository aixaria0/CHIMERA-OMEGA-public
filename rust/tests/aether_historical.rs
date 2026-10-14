use chimera_omega::{
    aether_historical::{verify_aether_historical_journal, CONTEXT_DOMAIN, REGISTRY_DOMAIN},
    aether_journal, aether_lattice, encoding,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, process::Command};

fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn pin(c: &Value) -> String {
    encoding::digest(CONTEXT_DOMAIN, c).unwrap()
}
fn fixture(name: &str) -> Value {
    serde_json::from_slice(
        &fs::read(format!(
            "{}/examples/aether-journal/{name}.export.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap()
}
fn registry(a: &Value) -> Value {
    let mut keys = BTreeMap::new();
    let mut policies = BTreeMap::new();
    let mut approvals = BTreeMap::new();
    let mut records = vec![&a["lineage"]["execution"]];
    if !a["lineage"]["parent"].is_null() {
        records.push(&a["lineage"]["parent"]);
    }
    for r in records {
        let receipt = &r["receipt"];
        let fp = receipt["attestation"]["key_fingerprint_sha256"]
            .as_str()
            .unwrap();
        let key_id = format!("key-{}", &fp[..16]);
        let policy_hash = receipt["policy_sha256"].as_str().unwrap();
        let policy_id = format!("policy-{}", &policy_hash[..16]);
        keys.insert(key_id.clone(),json!({"id":key_id,"public_key_hex":receipt["attestation"]["public_key_hex"],"fingerprint_sha256":fp,"status":"retired"}));
        policies.insert(policy_id.clone(),json!({"id":policy_id,"policy_revision":1,"operation":receipt["operation"],"executor_id":receipt["executor_id"],"deadline_ms":receipt["deadline_ms"],"policy_sha256":policy_hash,"status":"approved"}));
        approvals.insert(receipt["receipt_sha256"].as_str().unwrap().to_owned(),json!({"task_id":r["task_id"],"receipt_sha256":receipt["receipt_sha256"],"key_id":key_id,"policy_id":policy_id}));
    }
    json!({"schema":"chimera-aether-trust-registry/v1","source_repository":aether_lattice::AETHER_LATTICE_REPOSITORY,"lineage_source_revision":aether_lattice::AETHER_LATTICE_REVISION,
        "keys":keys.into_values().collect::<Vec<_>>(),"policies":policies.into_values().collect::<Vec<_>>(),"authorizations":approvals.into_values().collect::<Vec<_>>()})
}
fn context(a: &Value, r: &Value) -> Value {
    let journal = &a["lineage"]["certificate"]["evidence"]["journal"];
    json!({"schema":"chimera-aether-historical-context/v1","source_repository":aether_lattice::AETHER_LATTICE_REPOSITORY,"source_revision":aether_journal::EXPORT_REVISION,
        "registry_digest":encoding::digest(REGISTRY_DOMAIN,r).unwrap(),"journal_export_digest":encoding::digest(aether_journal::EXPORT_DOMAIN,a).unwrap(),
        "certificate_digest":encoding::digest(aether_lattice::CERTIFICATE_DOMAIN,&a["lineage"]["certificate"]).unwrap(),"journal_head_sha256":journal["head_hash"],"journal_event_count":journal["event_count"]})
}
fn check(a: &Value, r: &Value) -> Result<Value, String> {
    let c = context(a, r);
    verify_aether_historical_journal(&bytes(a), &bytes(r), &bytes(&c), &pin(&c))
        .map(|v| serde_json::to_value(v).unwrap())
}
fn assessment(a: &mut Value, current: &str) {
    let cert = &mut a["lineage"]["certificate"];
    cert["assessment"]["trusted_signer_fingerprint_sha256"] = current.into();
    cert["invariants"][1]["passed"] = false.into();
    if !cert["transformation"]["replay_of"].is_null() {
        cert["invariants"][8]["passed"] = false.into();
    }
    let failed: Vec<_> = cert["invariants"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["passed"] == false)
        .map(|i| i["name"].clone())
        .collect();
    cert["assessment"]["failed_invariants"] = json!(failed);
    cert["assessment"]["status"] = "rejected".into();
}
fn rehash_chain(a: &mut Value) {
    let mut previous: Option<String> = None;
    for e in a["journal"]["events"].as_array_mut().unwrap() {
        e["previous_hash"] = json!(previous);
        let mut h = Sha256::new();
        for part in [
            previous.as_deref().unwrap_or(""),
            e["event_id"].as_str().unwrap(),
            e["task_id"].as_str().unwrap(),
            e["event_type"].as_str().unwrap(),
            e["timestamp_ns_decimal"].as_str().unwrap(),
            e["payload_json"].as_str().unwrap(),
        ] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part.as_bytes());
        }
        previous = Some(format!("{:x}", h.finalize()));
        e["event_hash"] = json!(previous);
    }
    a["lineage"]["certificate"]["evidence"]["journal"]["head_hash"] = json!(previous);
}
// Test-only key; no persisted user or producer private identity is read.
fn sign_child(a: &mut Value, key: &SigningKey) {
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
    let record = &mut a["lineage"]["execution"];
    let output_hash = hash(record["output"].as_str().unwrap().as_bytes());
    let receipt = &mut record["receipt"];
    receipt["output_sha256"] = output_hash.into();
    let text = format!(
        "{{{}}}",
        fields
            .iter()
            .map(|k| format!(
                "{}:{}",
                serde_json::to_string(k).unwrap(),
                serde_json::to_string(&receipt[*k]).unwrap()
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    let digest = hash(text.as_bytes());
    let domain = "aether.execution-receipt.v1";
    let mut message = (domain.len() as u64).to_be_bytes().to_vec();
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(digest.as_bytes());
    let signature = key.sign(&message);
    key.verifying_key()
        .verify_strict(&message, &signature)
        .unwrap();
    let fp = hash(&key.verifying_key().to_bytes());
    receipt["receipt_sha256"] = digest.clone().into();
    receipt["attestation"] = json!({"algorithm":"ed25519","domain":domain,"public_key_hex":hex(&key.verifying_key().to_bytes()),"key_fingerprint_sha256":fp,"signature_hex":hex(&signature.to_bytes())});
    let record = a["lineage"]["execution"].clone();
    let receipt = &record["receipt"];
    let task = record["task_id"].as_str().unwrap();
    a["lineage"]["certificate"]["evidence"]["receipt"] = receipt.clone();
    a["lineage"]["certificate"]["artifacts"][1]["sha256"] = receipt["output_sha256"].clone();
    a["lineage"]["certificate"]["transformation"]["evidence_ref"] = digest.clone().into();
    for e in a["journal"]["events"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .filter(|e| e["task_id"] == task)
    {
        let mut payload: Value = serde_json::from_str(e["payload_json"].as_str().unwrap()).unwrap();
        if e["event_type"] == "RECEIPT_SIGNED" {
            payload["signer_fingerprint"] = fp.clone().into();
            payload["receipt_sha256"] = digest.clone().into();
        }
        if e["event_type"] == "VERIFICATION_PASSED" {
            payload["receipt_sha256"] = digest.clone().into();
        }
        e["payload_json"] = serde_json::to_string(&payload).unwrap().into();
    }
    assessment(a, &fp);
    rehash_chain(a);
}

#[test]
fn recorded_receipts_authorize_under_retired_keys_without_promoting_time_or_truth() {
    for name in ["echo", "uppercase", "sha256", "empty", "replay"] {
        let a = fixture(name);
        let r = registry(&a);
        let report = check(&a, &r).unwrap();
        for field in [
            "signature_integrity",
            "selected_policy_binding",
            "registry_authorization_binding",
            "journal_chain_integrity",
            "receipt_event_binding",
        ] {
            assert_eq!(report[field], "CONFIRMED");
        }
        for field in [
            "registry_freshness",
            "historical_time_authorization",
            "current_live_key_authorization",
            "external_journal_anchor",
            "independent_observation",
            "producer_binary_attestation",
        ] {
            assert_eq!(report[field], "UNKNOWN");
        }
        assert_eq!(report["runtime_reproduction"], "NOT_RUN");
        assert_eq!(report["omega_core_verdict"], "NOT_RUN");
        assert_eq!(
            report["authorizations"][0]["reviewer_key_status"],
            "retired"
        );
        assert_eq!(
            report["direct_replay_binding"],
            if name == "replay" {
                "CONFIRMED"
            } else {
                "NOT_APPLICABLE"
            }
        );
    }
}

#[test]
fn different_current_producer_view_is_preserved_instead_of_rewritten() {
    let mut a = fixture("echo");
    let r = registry(&a);
    assessment(&mut a, &"f".repeat(64));
    let saved = a.clone();
    let report = check(&a, &r).unwrap();
    assert_eq!(a, saved);
    assert_eq!(report["producer_view"]["assessment"], "rejected");
    assert_eq!(
        report["producer_view"]["selected_signer_fingerprint_sha256"],
        "f".repeat(64)
    );
    let old = json!({"schema":"chimera-aether-lineage-context/v1","source_repository":aether_lattice::AETHER_LATTICE_REPOSITORY,"source_revision":aether_lattice::AETHER_LATTICE_REVISION,
        "trusted_signer_fingerprint_sha256":a["lineage"]["execution"]["receipt"]["attestation"]["key_fingerprint_sha256"],"certificate_digest":context(&a,&r)["certificate_digest"],
        "journal_head_sha256":context(&a,&r)["journal_head_sha256"],"journal_event_count":context(&a,&r)["journal_event_count"]});
    assert!(aether_lattice::verify_aether_lineage(
        &bytes(&a["lineage"]),
        &bytes(&old),
        &encoding::digest(aether_lattice::CONTEXT_DOMAIN, &old).unwrap()
    )
    .is_err());
}

#[test]
fn replay_can_authenticate_two_separately_selected_signers() {
    let mut a = fixture("replay");
    sign_child(&mut a, &SigningKey::from_bytes(&[55; 32]));
    let r = registry(&a);
    let report = check(&a, &r).unwrap();
    assert_eq!(report["direct_replay_binding"], "CONFIRMED");
    assert_eq!(report["parent_receipt_event_binding"], "CONFIRMED");
    assert_ne!(
        report["authorizations"][0]["signer_fingerprint_sha256"],
        report["authorizations"][1]["signer_fingerprint_sha256"]
    );
    assert_eq!(report["producer_view"]["assessment"], "rejected");
    let mut missing = r.clone();
    let parent = a["lineage"]["parent"]["receipt"]["receipt_sha256"].clone();
    missing["authorizations"]
        .as_array_mut()
        .unwrap()
        .retain(|x| x["receipt_sha256"] != parent);
    assert!(check(&a, &missing).is_err());
}

#[test]
fn registry_context_and_export_replacement_cannot_choose_authority() {
    let a = fixture("echo");
    let r = registry(&a);
    let c = context(&a, &r);
    let expected = pin(&c);
    let mut changed = r.clone();
    changed["keys"][0]["status"] = "active".into();
    assert!(
        verify_aether_historical_journal(&bytes(&a), &bytes(&changed), &bytes(&c), &expected)
            .is_err()
    );
    let changed_context = context(&a, &changed);
    assert!(verify_aether_historical_journal(
        &bytes(&a),
        &bytes(&changed),
        &bytes(&changed_context),
        &expected
    )
    .is_err());
    assert_eq!(
        check(&a, &changed).unwrap()["current_live_key_authorization"],
        "UNKNOWN"
    );
    let mut changed = a.clone();
    changed["lineage"]["execution"]["output"] = "changed".into();
    assert!(
        verify_aether_historical_journal(&bytes(&changed), &bytes(&r), &bytes(&c), &expected)
            .is_err()
    );
    assert!(
        verify_aether_historical_journal(&bytes(&a), &bytes(&r), &bytes(&c), &"0".repeat(64))
            .is_err()
    );
}

#[test]
fn revocation_withdrawal_and_unlisted_or_transplanted_receipts_fail_closed() {
    let a = fixture("echo");
    let r = registry(&a);
    for (array, field, value) in [
        ("keys", "status", "revoked"),
        ("policies", "status", "withdrawn"),
        (
            "authorizations",
            "task_id",
            "00000000-0000-0000-0000-000000000000",
        ),
        ("authorizations", "receipt_sha256", &"0".repeat(64)),
        ("authorizations", "key_id", "missing"),
        ("authorizations", "policy_id", "missing"),
    ] {
        let mut changed = r.clone();
        changed[array][0][field] = value.into();
        assert!(check(&a, &changed).is_err());
    }
    assert!(check(&fixture("sha256"), &r).is_err());
}

#[test]
fn approved_valid_signatures_cannot_rescue_wrong_results_or_widen_policy() {
    let mut a = fixture("echo");
    a["lineage"]["execution"]["output"] = "incorrect signed output".into();
    sign_child(&mut a, &SigningKey::from_bytes(&[56; 32]));
    assert!(check(&a, &registry(&a)).is_err());
    let mut a = fixture("echo");
    a["lineage"]["execution"]["receipt"]["capabilities"] = 2.into();
    sign_child(&mut a, &SigningKey::from_bytes(&[57; 32]));
    assert!(check(&a, &registry(&a)).is_err());
    let a = fixture("echo");
    let r = registry(&a);
    for (field, value) in [
        ("policy_revision", json!(2)),
        ("deadline_ms", json!(10001)),
        ("operation", json!("shell")),
        ("executor_id", json!("unreviewed-executor")),
        ("policy_sha256", json!("0".repeat(64))),
    ] {
        let mut changed = r.clone();
        changed["policies"][0][field] = value;
        assert!(check(&a, &changed).is_err());
    }
}

#[test]
fn signature_corruption_and_key_substitution_fail_even_with_fresh_review_pin() {
    let a = fixture("echo");
    let r = registry(&a);
    let mut changed = a.clone();
    changed["lineage"]["execution"]["receipt"]["attestation"]["signature_hex"] =
        "0".repeat(128).into();
    changed["lineage"]["certificate"]["evidence"]["receipt"] =
        changed["lineage"]["execution"]["receipt"].clone();
    assert!(check(&changed, &r).is_err());
    let mut changed = r.clone();
    let k = SigningKey::from_bytes(&[58; 32]);
    changed["keys"][0]["public_key_hex"] = hex(&k.verifying_key().to_bytes()).into();
    changed["keys"][0]["fingerprint_sha256"] = hash(&k.verifying_key().to_bytes()).into();
    assert!(check(&a, &changed).is_err());
}

#[test]
fn journal_hash_omission_and_rehashed_foreign_receipt_events_are_rejected() {
    let a = fixture("echo");
    let r = registry(&a);
    let mut changed = a.clone();
    changed["journal"]["events"][0]["timestamp_ns_decimal"] = "1".into();
    assert!(check(&changed, &r).is_err());
    let mut changed = a.clone();
    changed["journal"]["events"].as_array_mut().unwrap().pop();
    assert!(check(&changed, &r).is_err());
    let mut changed = a.clone();
    let task = changed["lineage"]["execution"]["task_id"].clone();
    for e in changed["journal"]["events"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .filter(|e| e["task_id"] == task && e["event_type"] == "RECEIPT_SIGNED")
    {
        let mut p: Value = serde_json::from_str(e["payload_json"].as_str().unwrap()).unwrap();
        p["signer_fingerprint"] = "0".repeat(64).into();
        e["payload_json"] = serde_json::to_string(&p).unwrap().into();
    }
    rehash_chain(&mut changed);
    assert!(check(&changed, &r).is_err());
}

#[test]
fn duplicated_keys_policies_authorizations_and_ambiguous_tasks_are_rejected() {
    let a = fixture("echo");
    let r = registry(&a);
    for array in ["keys", "policies", "authorizations"] {
        let mut changed = r.clone();
        let item = changed[array][0].clone();
        changed[array].as_array_mut().unwrap().push(item);
        assert!(check(&a, &changed).is_err());
    }
    let mut changed = r.clone();
    let mut item = changed["keys"][0].clone();
    item["id"] = "zz-alias".into();
    changed["keys"].as_array_mut().unwrap().push(item);
    assert!(check(&a, &changed).is_err());
    let a = fixture("replay");
    let mut r = registry(&a);
    r["authorizations"][1]["task_id"] = r["authorizations"][0]["task_id"].clone();
    assert!(check(&a, &r).is_err());
}

#[test]
fn timestamps_do_not_create_validity_periods_or_registry_freshness() {
    let mut a = fixture("echo");
    for e in a["journal"]["events"].as_array_mut().unwrap() {
        e["timestamp_ns_decimal"] = "1".into();
    }
    rehash_chain(&mut a);
    let r = registry(&a);
    let report = check(&a, &r).unwrap();
    assert_eq!(report["historical_time_authorization"], "UNKNOWN");
    assert_eq!(report["registry_freshness"], "UNKNOWN");
    let mut changed = r.clone();
    changed["keys"][0]["valid_until"] = "tomorrow".into();
    assert!(check(&a, &changed).is_err());
}

#[test]
fn strict_shape_source_and_resource_limits_are_enforced() {
    let a = fixture("echo");
    let r = registry(&a);
    for (field, value) in [
        ("source_repository", "someone/else"),
        ("lineage_source_revision", "main"),
        ("schema", "chimera-aether-trust-registry/v2"),
    ] {
        let mut changed = r.clone();
        changed[field] = value.into();
        assert!(check(&a, &changed).is_err());
    }
    let c = context(&a, &r);
    let raw = String::from_utf8(bytes(&r)).unwrap();
    let duplicate = raw.replacen("{", "{\"schema\":\"chimera-aether-trust-registry/v1\",", 1);
    assert!(verify_aether_historical_journal(
        &bytes(&a),
        duplicate.as_bytes(),
        &bytes(&c),
        &pin(&c)
    )
    .is_err());
    for array in ["keys", "policies", "authorizations"] {
        let mut changed = r.clone();
        changed[array] = json!([]);
        assert!(check(&a, &changed).is_err());
    }
    let mut changed = a.clone();
    changed["lineage"].as_object_mut().unwrap().remove("parent");
    assert!(check(&changed, &r).is_err());
    let mut changed = a.clone();
    changed["lineage"]["execution"]["receipt"]
        .as_object_mut()
        .unwrap()
        .remove("parent_task_id");
    assert!(check(&changed, &r).is_err());
    let mut changed = r.clone();
    changed["authorizations"] = json!(vec![changed["authorizations"][0].clone(); 65]);
    assert!(check(&a, &changed).is_err());
    let huge = vec![b' '; encoding::MAX_BYTES + 1];
    assert!(verify_aether_historical_journal(&bytes(&a), &huge, &bytes(&c), &pin(&c)).is_err());
}

#[test]
fn recorded_historical_cli_reproduces_reports_and_keeps_input_files_read_only() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/aether-historical");
    for name in ["replay", "retired-view"] {
        let a = root.join(format!("{name}.export.json"));
        let r = root.join(format!("{name}.registry.json"));
        let c = root.join(format!("{name}.context.json"));
        let expected = fs::read_to_string(root.join(format!("{name}.context.sha256"))).unwrap();
        let before = [
            fs::read(&a).unwrap(),
            fs::read(&r).unwrap(),
            fs::read(&c).unwrap(),
        ];
        let run = |p: &str| {
            Command::new(env!("CARGO_BIN_EXE_omega"))
                .arg("verify-aether-historical-journal")
                .arg(&a)
                .arg("--registry")
                .arg(&r)
                .arg("--context")
                .arg(&c)
                .arg("--expect-context")
                .arg(p)
                .output()
                .unwrap()
        };
        let out = run(expected.trim());
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&out.stdout).unwrap(),
            serde_json::from_slice::<Value>(
                &fs::read(root.join(format!("{name}.report.json"))).unwrap()
            )
            .unwrap()
        );
        let bad = run(&"0".repeat(64));
        assert_eq!(bad.status.code(), Some(2));
        assert_eq!(
            [
                fs::read(a).unwrap(),
                fs::read(r).unwrap(),
                fs::read(c).unwrap()
            ],
            before
        );
    }
}
