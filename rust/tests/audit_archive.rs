use chimera_omega::{
    audit_archive::{verify_audit_archive, CONTEXT_DOMAIN, SOURCE_REPOSITORY, SOURCE_REVISION},
    encoding,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::Command;

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn pin(context: &Value) -> String {
    encoding::digest(CONTEXT_DOMAIN, context).unwrap()
}
fn fixture() -> (Value, Value) {
    (
        serde_json::from_slice(include_bytes!(
            "../../examples/audit-archive/read-capture.archive.json"
        ))
        .unwrap(),
        serde_json::from_slice(include_bytes!(
            "../../examples/audit-archive/read-capture.context.json"
        ))
        .unwrap(),
    )
}
fn check(a: &Value, c: &Value) -> Result<Value, String> {
    verify_audit_archive(&bytes(a), &bytes(c), &pin(c)).map(|r| serde_json::to_value(r).unwrap())
}
fn set_manifest(a: &mut Value, c: &mut Value, manifest: String) {
    c["manifest_sha256"] = hash(manifest.as_bytes()).into();
    a["manifest_chunks"] = json!(manifest
        .as_bytes()
        .chunks(4096)
        .map(|b| std::str::from_utf8(b).unwrap())
        .collect::<Vec<_>>());
}
fn synthetic(count: usize, length: usize) -> (Value, Value) {
    let content = "x".repeat(length);
    let chunks: Vec<_> = if content.is_empty() {
        vec![""]
    } else {
        content
            .as_bytes()
            .chunks(4096)
            .map(|b| std::str::from_utf8(b).unwrap())
            .collect()
    };
    let mut manifest = String::new();
    let mut artifacts = Vec::new();
    let mut selection = Vec::new();
    for i in 0..count {
        let path = format!("state/{i:02}.json");
        manifest.push_str(&format!("{}  {path}\n", hash(content.as_bytes())));
        artifacts.push(json!({"path":path,"content_chunks":chunks}));
        selection.push(json!({"path":path,"role":"raw_observation","surface":"live_pos"}));
    }
    (
        json!({"schema":"chimera-audit-archive/v1","source_repository":SOURCE_REPOSITORY,
        "source_revision":SOURCE_REVISION,"archive_id":"synthetic/local-only",
        "manifest_chunks":[manifest],"artifacts":artifacts}),
        json!({"schema":"chimera-audit-archive-context/v1","source_repository":SOURCE_REPOSITORY,
        "source_revision":SOURCE_REVISION,"archive_id":"synthetic/local-only",
        "manifest_sha256":hash(manifest.as_bytes()),"selection":selection}),
    )
}

#[test]
fn captured_archive_reproduces_binding_and_preserves_unknowns() {
    let (a, c) = fixture();
    assert_eq!(
        pin(&c),
        include_str!("../../examples/audit-archive/read-capture.context.sha256").trim()
    );
    let report = check(&a, &c).unwrap();
    assert_eq!(report["status"], "ARCHIVE_BINDING_CONFIRMED");
    assert_eq!(report["selected_file_count"], 6);
    assert_eq!(report["manifest_file_count"], 8);
    assert_eq!(report["archive_coverage"], "SELECTED_MANIFEST_FILES_ONLY");
    assert_eq!(
        report["unavailable_artifacts"],
        json!(["explore-by-hash.request.json", "fn_pos_info.rho"])
    );
    assert_eq!(
        report,
        serde_json::from_slice::<Value>(include_bytes!(
            "../../examples/audit-archive/read-capture.report.json"
        ))
        .unwrap()
    );
    for key in [
        "source_execution_authenticity",
        "independent_observation",
        "external_archive_anchor",
        "production_impact",
        "consensus_finality",
    ] {
        assert_eq!(report[key], "UNKNOWN");
    }
    for key in ["finding_verdict", "target_execution", "omega_core_verdict"] {
        assert_eq!(report[key], "NOT_RUN");
    }
    for artifact in report["artifacts"].as_array().unwrap() {
        assert_eq!(artifact["artifact_integrity"], "CONFIRMED");
        assert_eq!(artifact["observational_authenticity"], "UNKNOWN");
    }
}

#[test]
fn external_pin_prevents_context_and_role_substitution() {
    let (a, mut c) = fixture();
    let original = pin(&c);
    for bad in ["", &"0".repeat(64), &original.to_uppercase()] {
        assert!(verify_audit_archive(&bytes(&a), &bytes(&c), bad).is_err());
    }
    c["selection"][0]["surface"] = "finalized_history".into();
    assert!(verify_audit_archive(&bytes(&a), &bytes(&c), &original).is_err());
    // A freshly selected reviewer context can change a declared scope, never its authenticity.
    let report = check(&a, &c).unwrap();
    assert_eq!(report["consensus_finality"], "UNKNOWN");
    assert_eq!(
        report["artifacts"][0]["observational_authenticity"],
        "UNKNOWN"
    );
}

#[test]
fn changed_bytes_and_producer_resealed_manifest_cannot_replace_reviewed_seal() {
    let (a, c) = fixture();
    let original = pin(&c);
    let mut changed = a.clone();
    changed["artifacts"][0]["content_chunks"][0] = "altered capture".into();
    assert!(check(&changed, &c).is_err());
    let mut altered_context = c.clone();
    let old_hash = hash(
        a["artifacts"][0]["content_chunks"][0]
            .as_str()
            .unwrap()
            .as_bytes(),
    );
    let m = a["manifest_chunks"][0]
        .as_str()
        .unwrap()
        .replace(&old_hash, &hash(b"altered capture"));
    set_manifest(&mut changed, &mut altered_context, m);
    assert!(check(&changed, &c).is_err());
    assert!(verify_audit_archive(&bytes(&changed), &bytes(&altered_context), &original).is_err());
    assert_eq!(
        check(&changed, &altered_context).unwrap()["finding_verdict"],
        "NOT_RUN"
    );
}

#[test]
fn source_revision_repository_archive_and_schema_are_bound() {
    let (a, c) = fixture();
    for (key, value) in [
        ("source_repository", "someone/else"),
        ("source_revision", "main"),
        ("archive_id", "other/run"),
        ("schema", "chimera-audit-archive/v2"),
    ] {
        let mut altered = a.clone();
        altered[key] = value.into();
        assert!(check(&altered, &c).is_err());
    }
    for (key, value) in [
        ("source_repository", "someone/else"),
        ("source_revision", "main"),
        ("schema", "chimera-audit-archive-context/v2"),
    ] {
        let mut altered = c.clone();
        altered[key] = value.into();
        assert!(check(&a, &altered).is_err());
    }
}

#[test]
fn missing_duplicate_extra_and_unselected_artifacts_are_rejected() {
    let (a, c) = fixture();
    let mut changed = a.clone();
    changed["artifacts"].as_array_mut().unwrap().pop();
    assert!(check(&changed, &c).is_err());
    let mut changed = a.clone();
    changed["artifacts"][1] = changed["artifacts"][0].clone();
    assert!(check(&changed, &c).is_err());
    let mut changed = a.clone();
    let extra = changed["artifacts"][0].clone();
    changed["artifacts"].as_array_mut().unwrap().push(extra);
    assert!(check(&changed, &c).is_err());
    let (mut a, mut c) = synthetic(2, 1);
    c["selection"].as_array_mut().unwrap().pop();
    a["artifacts"].as_array_mut().unwrap().remove(0);
    assert!(check(&a, &c).is_err());
}

#[test]
fn unsafe_paths_and_invalid_role_surface_pairs_are_rejected() {
    let (a, c) = fixture();
    for path in [
        "../capture.json",
        "/capture.json",
        "state//capture.json",
        "state/./capture.json",
        "state\\capture.json",
        "a b.json",
        "a\n.json",
    ] {
        let mut changed = c.clone();
        changed["selection"][0]["path"] = path.into();
        assert!(check(&a, &changed).is_err());
        let mut changed = a.clone();
        changed["artifacts"][0]["path"] = path.into();
        assert!(check(&changed, &c).is_err());
    }
    for (index, key, value) in [
        (0, "surface", "not_applicable"),
        (1, "surface", "live_pos"),
        (0, "role", "producer_claim"),
        (0, "surface", "guaranteed_finality"),
    ] {
        let mut changed = c.clone();
        changed["selection"][index][key] = value.into();
        assert!(check(&a, &changed).is_err());
    }
    let mut changed = c.clone();
    changed["selection"][1] = changed["selection"][0].clone();
    assert!(check(&a, &changed).is_err());
}

#[test]
fn manifest_grammar_rejects_malleability_even_with_new_pin() {
    let (a, c) = synthetic(2, 1);
    let original = a["manifest_chunks"][0].as_str().unwrap();
    let lines: Vec<_> = original.lines().collect();
    let variants = [
        original.trim_end().to_owned(),
        original.replace('\n', "\r\n"),
        original.replace("  ", " "),
        format!("{}\n{}\n", lines[1], lines[0]),
        format!("{}\n{}\n", lines[0], lines[0]),
        format!("{original}\n"),
        original.replace("state/00.json", "../00.json"),
        original.replace("state/00.json", "manifest.sha256"),
        original.replace(&hash(b"x"), &hash(b"x").to_uppercase()),
    ];
    for manifest in variants {
        let (mut a, mut c) = (a.clone(), c.clone());
        set_manifest(&mut a, &mut c, manifest);
        assert!(check(&a, &c).is_err());
    }
}

#[test]
fn resource_limits_bound_files_manifest_chunks_and_aggregate_content() {
    let (a, c) = synthetic(1, 65_536);
    assert!(check(&a, &c).is_ok());
    let (a, c) = synthetic(1, 65_537);
    assert!(check(&a, &c).is_err());
    let (a, c) = synthetic(8, 65_536);
    assert!(check(&a, &c).is_ok());
    let (a, c) = synthetic(9, 65_536);
    assert!(check(&a, &c).is_err());
    let (a, c) = synthetic(32, 0);
    assert!(check(&a, &c).is_ok());
    let (a, c) = synthetic(33, 0);
    assert!(check(&a, &c).is_err());
    let (mut a, c) = synthetic(1, 0);
    a["artifacts"][0]["content_chunks"] = json!(vec![""; 33]);
    assert!(check(&a, &c).is_err());
    let (mut a, c) = synthetic(1, 0);
    a["artifacts"][0]["content_chunks"] = json!([]);
    assert!(check(&a, &c).is_err());
    let (mut a, c) = synthetic(1, 0);
    a["artifacts"][0]["content_chunks"] = json!(["x".repeat(4097)]);
    assert!(check(&a, &c).is_err());
    let (mut a, mut c) = synthetic(1, 0);
    let mut manifest = String::new();
    for i in 0..65 {
        manifest.push_str(&format!("{}  state/{i:02}.json\n", hash(b"")));
    }
    set_manifest(&mut a, &mut c, manifest);
    assert!(check(&a, &c).is_err());
}

#[test]
fn raw_utf8_bytes_remain_opaque_and_chunk_boundaries_do_not_change_identity() {
    let (mut a, mut c) = synthetic(1, 0);
    let raw = "{\"n\":9007199254740993,\"fraction\":0.1,\"n\":-1}\nمتن\u{0}";
    a["artifacts"][0]["content_chunks"] = json!([raw]);
    set_manifest(
        &mut a,
        &mut c,
        format!("{}  state/00.json\n", hash(raw.as_bytes())),
    );
    let before = check(&a, &c).unwrap();
    a["artifacts"][0]["content_chunks"] = json!([&raw[..10], &raw[10..]]);
    assert_eq!(check(&a, &c).unwrap(), before);
    assert_eq!(before["artifacts"][0]["byte_count"], raw.len());
    assert_eq!(before["finding_verdict"], "NOT_RUN");
}

#[test]
fn duplicate_json_keys_unknown_fields_and_missing_roles_do_not_normalize() {
    let (a, c) = fixture();
    let archive = String::from_utf8(bytes(&a)).unwrap();
    let duplicate = archive.replacen("{", "{\"schema\":\"chimera-audit-archive/v1\",", 1);
    assert!(verify_audit_archive(duplicate.as_bytes(), &bytes(&c), &pin(&c)).is_err());
    for target in ["archive", "context", "selection", "artifact"] {
        let (mut a, mut c) = (a.clone(), c.clone());
        match target {
            "archive" => a["finding_verdict"] = "CONFIRMED".into(),
            "context" => c["accepted"] = true.into(),
            "selection" => c["selection"][0]["accepted"] = true.into(),
            _ => a["artifacts"][0]["role"] = "raw_observation".into(),
        }
        assert!(check(&a, &c).is_err());
    }
    let mut altered = c.clone();
    altered["selection"][0]
        .as_object_mut()
        .unwrap()
        .remove("surface");
    assert!(check(&a, &altered).is_err());
    let huge = vec![b' '; encoding::MAX_BYTES + 1];
    assert!(verify_audit_archive(&huge, &bytes(&c), &pin(&c)).is_err());
}

#[test]
fn all_manifest_coverage_does_not_promote_truth_and_reordering_is_deterministic() {
    let (mut a, c) = synthetic(2, 1);
    let report = check(&a, &c).unwrap();
    assert_eq!(report["archive_coverage"], "ALL_MANIFEST_FILES");
    assert_eq!(report["unavailable_artifacts"], json!([]));
    assert_eq!(report["source_execution_authenticity"], "UNKNOWN");
    a["artifacts"].as_array_mut().unwrap().reverse();
    assert_eq!(check(&a, &c).unwrap(), report);
}

#[test]
fn cli_is_read_only_and_distinguishes_valid_binding_from_bad_pin() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/audit-archive");
    let a = root.join("read-capture.archive.json");
    let c = root.join("read-capture.context.json");
    let before_a = std::fs::read(&a).unwrap();
    let before_c = std::fs::read(&c).unwrap();
    let run = |p: &str| {
        Command::new(env!("CARGO_BIN_EXE_omega"))
            .arg("verify-audit-archive")
            .arg(&a)
            .arg("--context")
            .arg(&c)
            .arg("--expect-context")
            .arg(p)
            .output()
            .unwrap()
    };
    let valid =
        run(include_str!("../../examples/audit-archive/read-capture.context.sha256").trim());
    assert!(valid.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&valid.stdout).unwrap()["finding_verdict"],
        "NOT_RUN"
    );
    let invalid = run(&"0".repeat(64));
    assert_eq!(invalid.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&invalid.stdout).unwrap()["status"],
        "REJECTED"
    );
    assert_eq!(std::fs::read(a).unwrap(), before_a);
    assert_eq!(std::fs::read(c).unwrap(), before_c);
}
