use chimera_omega::compiler::{import_compiler_evidence, CompilerStatus};
use sha2::{Digest, Sha256};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/compiler/");
fn bytes(name: &str, ext: &str) -> Vec<u8> {
    std::fs::read(format!("{ROOT}{name}.{ext}")).unwrap()
}
fn pin(report: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(report))
}

#[test]
fn compiler_pass_is_imported_with_limits_not_promoted_to_omega_verdict() {
    let package = bytes("match", "ndjson");
    let context = bytes("match", "context.json");
    let report = bytes("native-reports", "json");
    let imported =
        import_compiler_evidence(&package, &context, &report, &pin(&report), "match").unwrap();
    assert!(matches!(imported.compiler_status, CompilerStatus::Pass));
    assert_eq!(imported.status, "IMPORTED_NOT_OMEGA_VERIFIED");
    assert_eq!(
        imported.scope,
        "PINNED_COMPILER_REPORT_AND_PACKAGE_BINDING_ONLY"
    );
    assert!(imported
        .limitations
        .iter()
        .any(|s| s.contains("not recomputed by OMEGA")));
}

#[test]
fn preserves_compiler_blocked_result() {
    let package = bytes("unsupported", "ndjson");
    let context = bytes("unsupported", "context.json");
    let report = bytes("native-reports", "json");
    let imported =
        import_compiler_evidence(&package, &context, &report, &pin(&report), "unsupported")
            .unwrap();
    assert!(matches!(imported.compiler_status, CompilerStatus::Blocked));
}

#[test]
fn preserves_compiler_refutation_and_binding_failure() {
    let report = bytes("native-reports", "json");
    let refuted = import_compiler_evidence(
        &bytes("refuted", "ndjson"),
        &bytes("refuted", "context.json"),
        &report,
        &pin(&report),
        "refuted",
    )
    .unwrap();
    assert!(matches!(refuted.compiler_status, CompilerStatus::Fail));
    assert_eq!(refuted.compiler_code, "CLAIM_REFUTED");

    let misbound = import_compiler_evidence(
        &bytes("signed-wrong-input", "ndjson"),
        &bytes("signed-wrong-input", "context.json"),
        &report,
        &pin(&report),
        "signed-wrong-input",
    )
    .unwrap();
    assert!(matches!(misbound.compiler_status, CompilerStatus::Fail));
    assert_eq!(misbound.compiler_code, "BINDING_MISMATCH");
}

#[test]
fn rejects_report_tampering_and_package_context_transplant() {
    let package = bytes("match", "ndjson");
    let context = bytes("match", "context.json");
    let mut report = bytes("native-reports", "json");
    report.push(b' ');
    assert!(import_compiler_evidence(
        &package,
        &context,
        &report,
        &pin(&bytes("native-reports", "json")),
        "match"
    )
    .is_err());
    let report = bytes("native-reports", "json");
    let wrong_context = bytes("refuted", "context.json");
    assert!(
        import_compiler_evidence(&package, &wrong_context, &report, &pin(&report), "match")
            .is_err()
    );
}

#[test]
fn rejects_wrong_fixture_and_invalid_caller_pin() {
    let package = bytes("match", "ndjson");
    let context = bytes("match", "context.json");
    let report = bytes("native-reports", "json");
    assert!(
        import_compiler_evidence(&package, &context, &report, &pin(&report), "refuted").is_err()
    );
    assert!(import_compiler_evidence(&package, &context, &report, "sha256:0000", "match").is_err());
}
