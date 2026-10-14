use chimera_omega::{
    aether_journal::{verify_aether_journal, CONTEXT_DOMAIN, EXPORT_DOMAIN},
    aether_lattice, encoding,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, process::Command};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/aether-journal/");

fn fixture(name: &str) -> (Value, Value) {
    (
        serde_json::from_slice(&fs::read(format!("{ROOT}{name}.export.json")).unwrap()).unwrap(),
        serde_json::from_slice(&fs::read(format!("{ROOT}{name}.context.json")).unwrap()).unwrap(),
    )
}

fn refresh(export: &Value, context: &mut Value) {
    let certificate = &export["lineage"]["certificate"];
    context["lineage_context"]["certificate_digest"] =
        json!(encoding::digest(aether_lattice::CERTIFICATE_DOMAIN, certificate).unwrap());
    context["lineage_context"]["journal_head_sha256"] =
        certificate["evidence"]["journal"]["head_hash"].clone();
    context["lineage_context"]["journal_event_count"] =
        certificate["evidence"]["journal"]["event_count"].clone();
    context["journal_export_digest"] = json!(encoding::digest(EXPORT_DOMAIN, export).unwrap());
}

fn check(export: &Value, context: &Value) -> Result<Value, String> {
    let report = verify_aether_journal(
        &serde_json::to_vec(export).unwrap(),
        &serde_json::to_vec(context).unwrap(),
        &encoding::digest(CONTEXT_DOMAIN, context).unwrap(),
    )?;
    Ok(serde_json::to_value(report).unwrap())
}

fn rechain(export: &mut Value) {
    let events = export["journal"]["events"].as_array_mut().unwrap();
    let mut previous: Option<String> = None;
    for (index, event) in events.iter_mut().enumerate() {
        event["sequence"] = json!(index + 1);
        event["previous_hash"] = json!(previous);
        let mut hash = Sha256::new();
        for part in [
            previous.as_deref().unwrap_or(""),
            event["event_id"].as_str().unwrap(),
            event["task_id"].as_str().unwrap(),
            event["event_type"].as_str().unwrap(),
            event["timestamp_ns_decimal"].as_str().unwrap(),
            event["payload_json"].as_str().unwrap(),
        ] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part.as_bytes());
        }
        previous = Some(format!("{:x}", hash.finalize()));
        event["event_hash"] = json!(previous);
    }
    let count = events.len();
    export["lineage"]["certificate"]["evidence"]["journal"]["head_hash"] = json!(previous);
    export["lineage"]["certificate"]["evidence"]["journal"]["event_count"] = json!(count);
}

fn stage_one_passes(export: &Value, context: &Value) {
    let c = &context["lineage_context"];
    aether_lattice::verify_aether_lineage(
        &serde_json::to_vec(&export["lineage"]).unwrap(),
        &serde_json::to_vec(c).unwrap(),
        &encoding::digest(aether_lattice::CONTEXT_DOMAIN, c).unwrap(),
    )
    .unwrap();
}

#[test]
fn real_complete_exports_reproduce_reports_and_preserve_unknowns() {
    for name in ["echo", "uppercase", "sha256", "empty", "replay"] {
        let (export, context) = fixture(name);
        let report = check(&export, &context).unwrap();
        let recorded: Value =
            serde_json::from_slice(&fs::read(format!("{ROOT}{name}.report.json")).unwrap())
                .unwrap();
        assert_eq!(report, recorded);
        assert_eq!(report["journal_chain_integrity"], "CONFIRMED");
        assert_eq!(report["receipt_event_binding"], "CONFIRMED");
        assert_eq!(
            report["parent_receipt_event_binding"],
            if name == "replay" {
                "CONFIRMED"
            } else {
                "NOT_APPLICABLE"
            }
        );
        for field in [
            "external_journal_anchor",
            "independent_observation",
            "producer_binary_attestation",
        ] {
            assert_eq!(report[field], "UNKNOWN");
        }
        assert_eq!(report["omega_core_verdict"], "NOT_RUN");
        assert_eq!(
            report["lineage_binding"]["journal_chain_integrity"],
            "UNKNOWN"
        );
    }
}

#[test]
fn caller_pin_and_supported_export_revision_cannot_be_replaced() {
    let (export, context) = fixture("echo");
    assert!(verify_aether_journal(
        &serde_json::to_vec(&export).unwrap(),
        &serde_json::to_vec(&context).unwrap(),
        &"0".repeat(64)
    )
    .is_err());
    for field in [
        "source_revision",
        "source_repository",
        "journal_export_digest",
    ] {
        let mut wrong = context.clone();
        wrong[field] = json!("0".repeat(64));
        assert!(check(&export, &wrong).is_err(), "{field}");
    }
    let mut wrong = context.clone();
    wrong["lineage_context"]["trusted_signer_fingerprint_sha256"] = json!("0".repeat(64));
    assert!(check(&export, &wrong).is_err());
}

#[test]
fn missing_events_suffixes_and_unhashed_sequence_changes_fail_closed() {
    let (export, context) = fixture("echo");
    let count = export["journal"]["events"].as_array().unwrap().len();
    for index in [0, count / 2, count - 1] {
        let mut wrong = export.clone();
        let mut pin = context.clone();
        wrong["journal"]["events"]
            .as_array_mut()
            .unwrap()
            .remove(index);
        refresh(&wrong, &mut pin);
        assert!(check(&wrong, &pin).is_err());
    }
    for value in [0, 2, 999] {
        let mut wrong = export.clone();
        let mut pin = context.clone();
        wrong["journal"]["events"][0]["sequence"] = json!(value);
        refresh(&wrong, &mut pin);
        assert!(check(&wrong, &pin).is_err());
    }
    let mut wrong = export.clone();
    let mut pin = context.clone();
    wrong["journal"]["coverage"] = json!("suffix_only");
    refresh(&wrong, &mut pin);
    assert!(check(&wrong, &pin).is_err());
}

#[test]
fn raw_hash_transplants_and_duplicate_event_identities_are_rejected() {
    let (export, context) = fixture("echo");
    for field in [
        "event_hash",
        "previous_hash",
        "payload_json",
        "timestamp_ns_decimal",
    ] {
        let mut wrong = export.clone();
        let mut pin = context.clone();
        wrong["journal"]["events"][0][field] = json!("1");
        refresh(&wrong, &mut pin);
        assert!(check(&wrong, &pin).is_err(), "{field}");
    }
    let mut wrong = export.clone();
    let mut pin = context.clone();
    wrong["journal"]["events"][1]["event_id"] = wrong["journal"]["events"][0]["event_id"].clone();
    rechain(&mut wrong);
    refresh(&wrong, &mut pin);
    stage_one_passes(&wrong, &pin);
    assert!(check(&wrong, &pin).is_err());
}

#[test]
fn validly_rehashed_chains_cannot_rescue_foreign_receipt_events() {
    let (export, context) = fixture("echo");
    for (kind, field, replacement) in [
        ("RECEIPT_SIGNED", "receipt_sha256", "0".repeat(64)),
        ("RECEIPT_SIGNED", "signer_fingerprint", "0".repeat(64)),
        ("RECEIPT_SIGNED", "algorithm", "foreign".into()),
        (
            "VERIFICATION_PASSED",
            "executor_id",
            "foreign-executor".into(),
        ),
    ] {
        let mut wrong = export.clone();
        let mut pin = context.clone();
        let event = wrong["journal"]["events"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["event_type"] == kind)
            .unwrap();
        let mut payload: Value =
            serde_json::from_str(event["payload_json"].as_str().unwrap()).unwrap();
        payload[field] = json!(replacement);
        event["payload_json"] = json!(serde_json::to_string(&payload).unwrap());
        rechain(&mut wrong);
        refresh(&wrong, &mut pin);
        stage_one_passes(&wrong, &pin);
        assert!(check(&wrong, &pin).is_err(), "{kind}:{field}");
    }
}

#[test]
fn reversed_or_duplicated_attestation_events_fail_after_valid_rehashing() {
    let (export, context) = fixture("echo");
    let mut wrong = export.clone();
    let mut pin = context.clone();
    let events = wrong["journal"]["events"].as_array_mut().unwrap();
    let signed = events
        .iter()
        .position(|e| e["event_type"] == "RECEIPT_SIGNED")
        .unwrap();
    let verified = events
        .iter()
        .position(|e| e["event_type"] == "VERIFICATION_PASSED")
        .unwrap();
    events.swap(signed, verified);
    rechain(&mut wrong);
    refresh(&wrong, &mut pin);
    stage_one_passes(&wrong, &pin);
    assert!(check(&wrong, &pin).is_err());
    let mut wrong = export.clone();
    let mut pin = context.clone();
    let mut extra = wrong["journal"]["events"][signed].clone();
    extra["event_id"] = json!("ffffffff-ffff-4fff-afff-ffffffffffff");
    wrong["journal"]["events"]
        .as_array_mut()
        .unwrap()
        .push(extra);
    rechain(&mut wrong);
    refresh(&wrong, &mut pin);
    stage_one_passes(&wrong, &pin);
    assert!(check(&wrong, &pin).is_err());
}

#[test]
fn canonical_timestamp_grammar_is_enforced_without_claiming_freshness() {
    let (export, context) = fixture("echo");
    for value in ["01", "+1", "1.0", "0", "9223372036854775808"] {
        let mut wrong = export.clone();
        let mut pin = context.clone();
        wrong["journal"]["events"][0]["timestamp_ns_decimal"] = json!(value);
        rechain(&mut wrong);
        refresh(&wrong, &mut pin);
        stage_one_passes(&wrong, &pin);
        assert!(check(&wrong, &pin).is_err(), "{value}");
    }
    let mut changed = export.clone();
    let mut pin = context.clone();
    changed["journal"]["events"][0]["timestamp_ns_decimal"] = json!("1");
    rechain(&mut changed);
    refresh(&changed, &mut pin);
    let report = check(&changed, &pin).unwrap();
    assert_eq!(report["independent_observation"], "UNKNOWN");
}

#[test]
fn duplicate_keys_non_string_maps_and_noncanonical_payloads_fail_after_rehashing() {
    let (export, context) = fixture("echo");
    for value in [
        "{\"x\":\"a\",\"x\":\"b\"}",
        "{\"x\":true}",
        "{} ",
        "{\"z\":\"a\",\"a\":\"b\"}",
    ] {
        let mut wrong = export.clone();
        let mut pin = context.clone();
        wrong["journal"]["events"][0]["payload_json"] = json!(value);
        rechain(&mut wrong);
        refresh(&wrong, &mut pin);
        stage_one_passes(&wrong, &pin);
        assert!(check(&wrong, &pin).is_err(), "{value}");
    }
}

#[test]
fn replay_requires_parent_receipt_events_in_the_same_complete_chain() {
    let (mut export, mut context) = fixture("replay");
    let parent = export["lineage"]["parent"]["task_id"].clone();
    export["journal"]["events"]
        .as_array_mut()
        .unwrap()
        .retain(|e| !(e["task_id"] == parent && e["event_type"] == "RECEIPT_SIGNED"));
    rechain(&mut export);
    refresh(&export, &mut context);
    stage_one_passes(&export, &context);
    assert!(check(&export, &context).is_err());
}

#[test]
fn producer_rejection_flags_do_not_veto_independently_valid_journal_evidence() {
    let (mut export, mut context) = fixture("echo");
    let c = &mut export["lineage"]["certificate"];
    c["evidence"]["journal"]["valid"] = json!(false);
    c["evidence"]["journal"]["first_invalid_sequence"] = json!(1);
    c["invariants"][6]["passed"] = json!(false);
    c["assessment"]["status"] = json!("rejected");
    c["assessment"]["failed_invariants"] = json!(["journal_integrity"]);
    refresh(&export, &mut context);
    let report = check(&export, &context).unwrap();
    assert_eq!(report["journal_chain_integrity"], "CONFIRMED");
    assert_eq!(report["lineage_binding"]["producer_assessment"], "rejected");
}

#[test]
fn bounded_count_unknown_fields_and_cli_pin_rejection_are_enforced() {
    let (mut missing, mut pin) = fixture("echo");
    missing["journal"]["events"][0]
        .as_object_mut()
        .unwrap()
        .remove("previous_hash");
    refresh(&missing, &mut pin);
    stage_one_passes(&missing, &pin);
    assert!(check(&missing, &pin).is_err());
    let (mut export, mut context) = fixture("echo");
    let first = export["journal"]["events"][0].clone();
    export["journal"]["events"] = json!(vec![first; 257]);
    refresh(&export, &mut context);
    assert!(check(&export, &context).is_err());
    let (mut export, mut context) = fixture("echo");
    export["journal"]["invented_authority"] = json!(true);
    refresh(&export, &mut context);
    assert!(check(&export, &context).is_err());
    let pin = fs::read_to_string(format!("{ROOT}echo.context.sha256")).unwrap();
    for (selected, expected) in [
        (pin.trim(), 0),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            2,
        ),
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_omega"))
            .args([
                "verify-aether-journal",
                &format!("{ROOT}echo.export.json"),
                "--context",
                &format!("{ROOT}echo.context.json"),
                "--expect-context",
                selected,
            ])
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(expected));
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(
            report["status"],
            if expected == 0 {
                "CONFIRMED"
            } else {
                "REJECTED"
            }
        );
    }
}
