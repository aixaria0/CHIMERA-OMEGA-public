use chimera_omega::{
    encoding::{self, digest},
    model::{Overall, State},
    seal, verify,
};
use serde_json::{json, Value};

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("../../examples/v2/trace-match.json")).unwrap()
}
fn sealed(value: &Value) -> Value {
    serde_json::to_value(seal(&bytes(value)).unwrap()).unwrap()
}
fn pin(value: &Value) -> &str {
    value["digest"].as_str().unwrap()
}
fn check(value: &Value) -> chimera_omega::model::Report {
    verify(&bytes(value), pin(value)).unwrap()
}
fn body_mut<'a>(value: &'a mut Value, id: &str) -> &'a mut Value {
    value["evidence"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|n| n["body"]["id"] == id)
        .unwrap()
        .get_mut("body")
        .unwrap()
}
fn reject(value: &Value, message: &str) {
    let error = verify(&bytes(value), pin(value)).unwrap_err();
    assert!(
        error.contains(message),
        "expected {message:?}, got {error:?}"
    );
}

#[test]
fn positive_is_only_artifact_support() {
    let report = check(&fixture());
    assert_eq!(report.status, Overall::LocallySupported);
    assert_eq!(report.dimensions.artifact_conformance, State::Confirmed);
    assert_eq!(report.dimensions.negative_control, State::Pass);
    assert_eq!(report.dimensions.formal_proof, State::Unknown);
    assert_eq!(report.dimensions.implementation_binding, State::Unknown);
    assert_eq!(report.dimensions.runtime_reproduction, State::Unknown);
    assert_eq!(report.dimensions.independent_observation, State::Unknown);
    assert_eq!(report.dimensions.replay, State::NotRun);
    assert_eq!(report.dimensions.production_reachability, State::Unknown);
    assert_eq!(report.dimensions.finality_externality, State::Unknown);
}

#[test]
fn evidence_mutation_is_rejected() {
    let mut v = fixture();
    body_mut(&mut v, "observed")["payload"]["states"][1] = json!("f".repeat(64));
    reject(&v, "evidence digest mismatch");
}

#[test]
fn evidence_deletion_is_rejected() {
    let mut v = fixture();
    v["evidence"] = json!([]);
    reject(&v, "missing required evidence");
}

#[test]
fn duplicate_identifiers_are_rejected() {
    let mut v = fixture();
    let node = v["evidence"][0].clone();
    v["evidence"].as_array_mut().unwrap().push(node);
    reject(&v, "duplicate evidence id");
}

#[test]
fn dangling_provenance_is_rejected() {
    let mut v = fixture();
    body_mut(&mut v, "observed")["parents"] = json!(["absent"]);
    reject(&v, "dangling provenance");
}

#[test]
fn provenance_cycles_are_rejected() {
    let mut v = fixture();
    body_mut(&mut v, "expected")["parents"] = json!(["observed"]);
    body_mut(&mut v, "observed")["parents"] = json!(["expected"]);
    reject(&v, "provenance cycle");
}

#[test]
fn self_provenance_is_rejected() {
    let mut v = fixture();
    body_mut(&mut v, "expected")["parents"] = json!(["expected"]);
    reject(&v, "provenance cycle");
}

#[test]
fn revision_configuration_environment_and_claim_are_bound() {
    for field in ["revision", "configuration", "environment"] {
        let mut v = fixture();
        v["claim"]["target"][field] = json!("f".repeat(64));
        reject(&v, "binding mismatch");
    }
    for field in ["id", "statement"] {
        let mut v = fixture();
        v["claim"][field] = json!("different");
        reject(&v, "binding mismatch");
    }
    let mut v = fixture();
    v["claim"]["assumptions"] = json!(["incompatible assumption"]);
    reject(&v, "binding mismatch");
}

#[test]
fn all_schema_and_policy_versions_are_checked() {
    for field in ["schema", "policy"] {
        let mut v = fixture();
        v[field] = json!("unsupported/v999");
        reject(&v, "unsupported");
    }
    let mut v = fixture();
    v["claim"]["schema"] = json!("unsupported/v999");
    reject(&v, "unsupported");
    let mut v = fixture();
    body_mut(&mut v, "observed")["schema"] = json!("unsupported/v999");
    reject(&v, "unsupported");
}

#[test]
fn declared_dimensions_and_unknown_fields_are_rejected() {
    let mut v = fixture();
    v["dimensions"] = json!({"formal_proof":"PROVEN"});
    reject(&v, "unknown field");
    let mut v = fixture();
    v["claim"]["confidence"] = json!(100);
    reject(&v, "unknown field");
    let mut v = fixture();
    body_mut(&mut v, "observed")["payload"]["verified"] = json!(true);
    reject(&v, "unknown field");
}

#[test]
fn contradictory_observation_preserves_first_divergence() {
    let mut v = fixture();
    body_mut(&mut v, "observed")["payload"]["states"][1] = json!("f".repeat(64));
    let report = check(&sealed(&v));
    assert_eq!(report.status, Overall::Contradicted);
    let witness = report.comparisons[0].first_divergence.as_ref().unwrap();
    assert_eq!(witness.index, 1);
    assert_eq!(witness.previous.as_deref(), Some("0".repeat(64).as_str()));
    assert_eq!(witness.expected.as_deref(), Some("1".repeat(64).as_str()));
    assert_eq!(witness.observed.as_deref(), Some("f".repeat(64).as_str()));
    assert_eq!(report.controls[0].state, State::NotRun);
}

#[test]
fn one_contradiction_cannot_be_outvoted() {
    let mut v = fixture();
    let mut node = v["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["body"]["id"] == "observed")
        .unwrap()
        .clone();
    node["body"]["id"] = json!("contradiction");
    node["body"]["payload"]["states"][0] = json!("f".repeat(64));
    v["evidence"].as_array_mut().unwrap().push(node);
    v["claim"]["predicate"]["observed"] = json!(["observed", "contradiction"]);
    let report = check(&sealed(&v));
    assert_eq!(report.status, Overall::Contradicted);
    assert_eq!(report.comparisons.len(), 2);
}

#[test]
fn unreferenced_observation_cannot_be_hidden() {
    let mut v = fixture();
    let mut node = v["evidence"][0].clone();
    node["body"]["id"] = json!("hidden");
    v["evidence"].as_array_mut().unwrap().push(node);
    reject(&v, "unassigned evidence");
}

#[test]
fn missing_control_is_rejected_and_absent_obligation_is_inconclusive() {
    let mut v = fixture();
    v["evidence"]
        .as_array_mut()
        .unwrap()
        .retain(|n| n["body"]["id"] != "control");
    reject(&v, "missing required evidence");
    v["claim"]["predicate"]["negative_controls"] = json!([]);
    let report = check(&sealed(&v));
    assert_eq!(report.status, Overall::Inconclusive);
    assert_eq!(report.dimensions.negative_control, State::NotRun);
}

#[test]
fn no_observations_cannot_pass_vacuously() {
    let mut v = fixture();
    v["evidence"]
        .as_array_mut()
        .unwrap()
        .retain(|n| n["body"]["id"] == "expected");
    v["claim"]["predicate"]["observed"] = json!([]);
    v["claim"]["predicate"]["negative_controls"] = json!([]);
    let report = check(&sealed(&v));
    assert_eq!(report.status, Overall::Inconclusive);
    assert_eq!(report.dimensions.artifact_conformance, State::Unknown);
}

#[test]
fn noop_control_fails_without_contradicting_the_claim() {
    let mut v = fixture();
    body_mut(&mut v, "control")["payload"]["replacement"] = json!("1".repeat(64));
    let report = check(&sealed(&v));
    assert_eq!(report.status, Overall::Inconclusive);
    assert_eq!(report.dimensions.artifact_conformance, State::Confirmed);
    assert_eq!(report.dimensions.negative_control, State::Fail);
}

#[test]
fn control_provenance_and_bounds_are_enforced() {
    let mut v = fixture();
    body_mut(&mut v, "control")["parents"] = json!([]);
    reject(&v, "baseline provenance");
    let mut v = fixture();
    body_mut(&mut v, "control")["payload"]["index"] = json!(10);
    reject(&v, "outside baseline");
    let mut v = fixture();
    body_mut(&mut v, "control")["payload"]["baseline"] = json!("expected");
    body_mut(&mut v, "control")["parents"] = json!(["expected"]);
    reject(&v, "not an observation");
}

#[test]
fn reordered_sets_have_identical_digests_and_reports() {
    let v = fixture();
    let expected = serde_json::to_value(check(&v)).unwrap();
    let mut reversed = v.clone();
    reversed["evidence"].as_array_mut().unwrap().reverse();
    body_mut(&mut reversed, "control")["parents"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_eq!(sealed(&reversed), v);
    assert_eq!(serde_json::to_value(check(&reversed)).unwrap(), expected);
}

#[test]
fn trace_order_remains_semantic() {
    let mut v = fixture();
    body_mut(&mut v, "observed")["payload"]["states"]
        .as_array_mut()
        .unwrap()
        .reverse();
    reject(&v, "digest mismatch");
    assert_eq!(check(&sealed(&v)).status, Overall::Contradicted);
}

#[test]
fn node_envelope_and_caller_digests_are_checked() {
    let mut v = fixture();
    v["evidence"][0]["digest"] = json!("f".repeat(64));
    reject(&v, "evidence digest mismatch");
    let mut v = fixture();
    v["digest"] = json!("f".repeat(64));
    reject(&v, "envelope digest mismatch");
    assert!(verify(&bytes(&fixture()), &"f".repeat(64))
        .unwrap_err()
        .contains("caller pin mismatch"));
    assert!(verify(&bytes(&fixture()), "").is_err());
}

#[test]
fn rehashing_cannot_bypass_an_external_pin() {
    let v = fixture();
    let mut altered = v.clone();
    altered["claim"]["target"]["revision"] = json!("other");
    let altered = sealed(&altered);
    assert!(verify(&bytes(&altered), pin(&v))
        .unwrap_err()
        .contains("caller pin mismatch"));
}

#[test]
fn source_relabeling_cannot_gain_authority() {
    let mut v = fixture();
    body_mut(&mut v, "observed")["evidence_class"] = json!("RECORDED");
    reject(&v, "digest mismatch");
    let report = check(&sealed(&v));
    assert_eq!(report.dimensions.runtime_reproduction, State::Unknown);
    assert_eq!(report.dimensions.independent_observation, State::Unknown);
    let mut v = fixture();
    body_mut(&mut v, "observed")["evidence_class"] = json!("LIVE");
    reject(&v, "unknown variant");
    let mut v = fixture();
    body_mut(&mut v, "control")["evidence_class"] = json!("RECORDED");
    reject(&v, "remain synthetic");
}

#[test]
fn authority_and_signature_claims_are_unsupported() {
    let mut v = fixture();
    body_mut(&mut v, "observed")["signature"] = json!("pretend-signature");
    reject(&v, "unknown field");
    let mut v = fixture();
    v["claim"]["epistemic_state"] = json!("ESTABLISHED");
    reject(&v, "unknown variant");
}

#[test]
fn ai_producer_cannot_promote_dimensions() {
    let mut v = fixture();
    body_mut(&mut v, "observed")["producer"]["kind"] = json!("AI");
    let report = check(&sealed(&v));
    assert_eq!(report.dimensions.independent_observation, State::Unknown);
    assert_eq!(report.dimensions.formal_proof, State::Unknown);
}

#[test]
fn roles_and_parent_references_cannot_be_duplicated() {
    let mut v = fixture();
    v["claim"]["predicate"]["observed"] = json!(["observed", "observed"]);
    reject(&v, "duplicate reference");
    let mut v = fixture();
    v["claim"]["predicate"]["observed"] = json!(["expected", "observed"]);
    reject(&v, "disjoint");
    let mut v = fixture();
    body_mut(&mut v, "observed")["parents"] = json!(["expected", "expected"]);
    reject(&v, "duplicate reference");
}

#[test]
fn strict_parser_rejects_ambiguous_and_lossy_inputs() {
    for input in [
        r#"{"a":1,"a":2}"#,
        r#"{"x":{"a":1,"a":2}}"#,
        r#"{"a":1,"\u0061":2}"#,
        "9007199254740993",
        "-0",
        "-1",
        "1.0",
        "1e0",
        "NaN",
        "Infinity",
        r#""\ud800""#,
        "{} {}",
        r#"{"é":1}"#,
    ] {
        assert!(
            encoding::parse(input.as_bytes()).is_err(),
            "accepted {input}"
        );
    }
    assert!(encoding::parse(&[0xff]).is_err());
    assert_eq!(
        encoding::parse(b"9007199254740991").unwrap(),
        json!(9_007_199_254_740_991_u64)
    );
}

#[test]
fn canonical_encoding_is_explicit_and_domain_separated() {
    assert_eq!(
        encoding::canonical_json(&json!({"z":[2,1],"a":"سلام\n"})).unwrap(),
        "{\"a\":\"سلام\\n\",\"z\":[2,1]}"
    );
    assert_ne!(
        digest("claim/v2", &json!({})).unwrap(),
        digest("evidence-node/v1", &json!({})).unwrap()
    );
    assert!(encoding::canonical_json(&json!(1.5)).is_err());
    assert!(digest("bad\0domain", &json!({})).is_err());
}

#[test]
fn limits_and_malformed_inputs_fail_closed() {
    assert!(encoding::parse(&vec![b' '; encoding::MAX_BYTES + 1]).is_err());
    assert!(encoding::parse(format!("{}0{}", "[".repeat(33), "]".repeat(33)).as_bytes()).is_err());
    for input in ["null", "42", "[]", "{}", "true"] {
        assert!(verify(input.as_bytes(), pin(&fixture())).is_err());
    }
    let mut v = fixture();
    body_mut(&mut v, "observed")["payload"]["states"] = json!(vec!["0".repeat(64); 2049]);
    reject(&v, "1..2048");
}

#[test]
fn divergence_handles_initial_missing_and_extra_states() {
    use chimera_omega::first_divergence;
    let expected = vec!["a".to_string(), "b".to_string()];
    assert!(first_divergence(&expected, &expected).is_none());
    let first = first_divergence(&expected, &["x".into()]).unwrap();
    assert_eq!(first.index, 0);
    assert!(first.previous.is_none());
    let missing = first_divergence(&expected, &expected[..1]).unwrap();
    assert_eq!(missing.index, 1);
    assert!(missing.observed.is_none());
    let extra = first_divergence(&expected[..1], &expected).unwrap();
    assert_eq!(extra.index, 1);
    assert!(extra.expected.is_none());
}

#[test]
fn checked_in_receipt_recomputes_exactly() {
    let expected: Value =
        serde_json::from_str(include_str!("../../examples/v2/trace-match.report.json")).unwrap();
    assert_eq!(serde_json::to_value(check(&fixture())).unwrap(), expected);
}

#[test]
fn evidence_cannot_be_transplanted_from_another_claim() {
    let mut other = fixture();
    other["claim"]["id"] = json!("another-claim");
    let other = sealed(&other);
    let mut v = fixture();
    v["evidence"][0] = other["evidence"][0].clone();
    reject(&v, "binding mismatch");
}

#[test]
fn sealing_cannot_emit_an_unreadably_large_package() {
    let mut v = fixture();
    v["claim"]["predicate"]["negative_controls"] = json!([]);
    v["claim"]["predicate"]["observed"] = json!([]);
    let mut node = v["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["body"]["id"] == "expected")
        .unwrap()
        .clone();
    node["body"]["payload"]["states"] = json!(vec!["0".repeat(64); 50]);
    v["evidence"] = json!([node.clone()]);
    for index in 0..230 {
        let id = format!("observation-{index}");
        node["body"]["id"] = json!(id);
        v["evidence"].as_array_mut().unwrap().push(node.clone());
        v["claim"]["predicate"]["observed"]
            .as_array_mut()
            .unwrap()
            .push(json!(id));
    }
    assert!(bytes(&v).len() < encoding::MAX_BYTES);
    assert!(seal(&bytes(&v))
        .unwrap_err()
        .contains("sealed package exceeds"));
}

#[test]
fn not_applicable_is_not_unknown() {
    assert_ne!(
        serde_json::to_value(State::NotApplicable).unwrap(),
        serde_json::to_value(State::Unknown).unwrap()
    );
    // The current policy never infers non-applicability from missing evidence.
    assert!(!serde_json::to_string(&check(&fixture()).dimensions)
        .unwrap()
        .contains("NOT_APPLICABLE"));
}

#[test]
fn multiple_observations_each_require_control_coverage() {
    let mut v = fixture();
    let mut other = v["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["body"]["id"] == "observed")
        .unwrap()
        .clone();
    other["body"]["id"] = json!("observed2");
    v["evidence"].as_array_mut().unwrap().push(other);
    v["claim"]["predicate"]["observed"] = json!(["observed2", "observed"]);
    assert_eq!(check(&sealed(&v)).status, Overall::Inconclusive);
    let mut control = v["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["body"]["id"] == "control")
        .unwrap()
        .clone();
    control["body"]["id"] = json!("control2");
    control["body"]["payload"]["baseline"] = json!("observed2");
    control["body"]["parents"] = json!(["observed2", "expected"]);
    v["evidence"].as_array_mut().unwrap().push(control);
    v["claim"]["predicate"]["negative_controls"] = json!(["control2", "control"]);
    let v = sealed(&v);
    assert_eq!(check(&v).status, Overall::LocallySupported);
    let mut reversed = v.clone();
    reversed["claim"]["predicate"]["observed"]
        .as_array_mut()
        .unwrap()
        .reverse();
    reversed["claim"]["predicate"]["negative_controls"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_eq!(
        serde_json::to_value(check(&v)).unwrap(),
        serde_json::to_value(check(&reversed)).unwrap()
    );
}

#[test]
fn cli_replays_in_fresh_processes_and_rejects_corruption() {
    use std::{fs, process::Command};
    let temp = std::env::temp_dir().join(format!("omega-cli-test-{}", std::process::id()));
    fs::create_dir(&temp).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(temp.clone());
    let package = temp.join("package.json");
    let receipt = temp.join("receipt.json");
    let v = fixture();
    fs::write(&package, bytes(&v)).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_omega"))
            .args(args)
            .output()
            .unwrap()
    };
    let args = ["verify", package.to_str().unwrap(), "--expect", pin(&v)];
    let first = run(&args);
    let second = run(&args);
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(first.stdout, second.stdout);
    fs::write(&receipt, &first.stdout).unwrap();
    let replay_args = [
        "replay",
        package.to_str().unwrap(),
        "--expect",
        pin(&v),
        "--receipt",
        receipt.to_str().unwrap(),
    ];
    let replay = run(&replay_args);
    assert_eq!(replay.status.code(), Some(0));
    let result: Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(result["status"], "REPRODUCED");
    assert_eq!(
        result["report"]["dimensions"]["runtime_reproduction"],
        "UNKNOWN"
    );
    let mut forged: Value = serde_json::from_slice(&first.stdout).unwrap();
    forged["dimensions"]["formal_proof"] = json!("PROVEN");
    fs::write(&receipt, bytes(&forged)).unwrap();
    let replay = run(&replay_args);
    assert_eq!(replay.status.code(), Some(1));
    assert_eq!(
        serde_json::from_slice::<Value>(&replay.stdout).unwrap()["status"],
        "DIVERGENT"
    );

    let mut altered = v.clone();
    body_mut(&mut altered, "observed")["payload"]["states"][1] = json!("f".repeat(64));
    fs::write(&package, bytes(&altered)).unwrap();
    let corrupted = run(&args);
    assert_eq!(corrupted.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&corrupted.stdout).unwrap()["status"],
        "REJECTED"
    );
    let sealed = sealed(&altered);
    fs::write(&package, bytes(&sealed)).unwrap();
    let contradicted = run(&[
        "verify",
        package.to_str().unwrap(),
        "--expect",
        pin(&sealed),
    ]);
    assert_eq!(contradicted.status.code(), Some(1));
    body_mut(&mut altered, "observed")["payload"]["states"][1] = json!("1".repeat(64));
    body_mut(&mut altered, "control")["payload"]["replacement"] = json!("1".repeat(64));
    let incomplete = serde_json::to_value(seal(&bytes(&altered)).unwrap()).unwrap();
    fs::write(&package, bytes(&incomplete)).unwrap();
    assert_eq!(
        run(&[
            "verify",
            package.to_str().unwrap(),
            "--expect",
            pin(&incomplete)
        ])
        .status
        .code(),
        Some(3)
    );
    fs::write(&package, b"{bad json").unwrap();
    assert_eq!(run(&args).status.code(), Some(2));
    assert_eq!(run(&[]).status.code(), Some(2));
    assert_eq!(
        run(&["verify", "missing-omega-package.json", "--expect", pin(&v)])
            .status
            .code(),
        Some(2)
    );
}
