//! Strict import boundary for RCHAIN-COMPLIER assurance packages.
//!
//! This module verifies byte/package/context binding and the pinned Compiler
//! report envelope. It intentionally does not reimplement Compiler's Ed25519
//! event verifier or promote its report to an OMEGA verdict.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const COMPILER_REPOSITORY: &str = "aixaria0/RCHAIN-COMPLIER";
pub const COMPILER_REVISION: &str = "ef9b8b70fa1212bda57fed24cbbc3ddebb5aaf81";
const PACKAGE_SCHEMA: &str = "assurance-evidence-package/v1";
const REPORT_SCHEMA: &str = "chimera-compiler-conformance/v1";
const CONTEXT_SCHEMA: &str = "chimera-rchain-compiler-context/v1";
const MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerContext {
    pub schema: String,
    #[serde(rename = "expectedPolicyDigest")]
    pub expected_policy_digest: String,
    #[serde(rename = "expectedTaskId")]
    pub expected_task_id: String,
    #[serde(rename = "expectedClaimId")]
    pub expected_claim_id: String,
    #[serde(rename = "expectedPackageDigest")]
    pub expected_package_digest: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    #[serde(rename = "canonicalProfile")]
    canonical_profile: String,
    policy: Value,
    #[serde(rename = "policyDigest")]
    policy_digest: String,
    #[serde(rename = "taskId")]
    task_id: String,
    #[serde(rename = "taskEventId")]
    task_event_id: String,
    #[serde(rename = "claimId")]
    claim_id: String,
    #[serde(rename = "eventRoot")]
    event_root: String,
    #[serde(rename = "eventCount")]
    event_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogReport {
    schema: String,
    status: CompilerStatus,
    code: String,
    reason: String,
    #[serde(rename = "packageDigest")]
    package_digest: String,
    #[serde(rename = "eventRoot")]
    event_root: Option<String>,
    #[serde(rename = "taskId")]
    task_id: String,
    #[serde(rename = "claimId")]
    claim_id: String,
    #[serde(rename = "eventCount")]
    event_count: usize,
    #[serde(rename = "verifierActorIds")]
    verifier_actor_ids: Vec<String>,
    operation: Option<String>,
    limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompilerStatus {
    Pass,
    Fail,
    Blocked,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntry {
    name: String,
    native: CatalogReport,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConformanceReport {
    schema: String,
    repository: String,
    revision: String,
    #[serde(rename = "evidenceClass")]
    evidence_class: String,
    #[serde(rename = "canonicalProbe")]
    canonical_probe: String,
    catalog: Vec<CatalogEntry>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompilerImport {
    pub schema: &'static str,
    pub status: &'static str,
    pub scope: &'static str,
    pub repository: &'static str,
    pub revision: &'static str,
    pub fixture: String,
    pub package_digest: String,
    pub compiler_status: CompilerStatus,
    pub compiler_code: String,
    pub task_id: String,
    pub claim_id: String,
    pub policy_digest: String,
    pub event_count: usize,
    pub event_root: String,
    pub verifier_actor_ids: Vec<String>,
    pub operation: Option<String>,
    pub limitations: Vec<&'static str>,
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn package_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PACKAGE_SCHEMA.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

/// Imports a package only when its raw bytes, Compiler manifest, caller context,
/// and pinned Compiler-generated conformance report all agree.
pub fn import_compiler_evidence(
    package: &[u8],
    context_bytes: &[u8],
    report_bytes: &[u8],
    expected_report_digest: &str,
    fixture_name: &str,
) -> Result<CompilerImport, String> {
    if package.len() > MAX_BYTES || context_bytes.len() > 16_384 || report_bytes.len() > 1_048_576 {
        return Err("compiler artifact exceeds resource limit".into());
    }
    if !digest(expected_report_digest) || sha256(report_bytes) != expected_report_digest {
        return Err("caller-pinned Compiler report digest mismatch".into());
    }
    let context: CompilerContext = serde_json::from_slice(context_bytes)
        .map_err(|e| format!("invalid Compiler context: {e}"))?;
    if context.schema != CONTEXT_SCHEMA
        || !digest(&context.expected_policy_digest)
        || !digest(&context.expected_task_id)
        || !digest(&context.expected_claim_id)
        || !digest(&context.expected_package_digest)
    {
        return Err("unsupported or invalid Compiler context".into());
    }
    let package_hash = package_digest(package);
    if package_hash != context.expected_package_digest {
        return Err("package bytes do not match caller context".into());
    }
    let text = std::str::from_utf8(package).map_err(|_| "Compiler package is not UTF-8")?;
    if !text.ends_with('\n') {
        return Err("Compiler package must be LF-terminated NDJSON".into());
    }
    let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
    if lines.len() < 2 || lines.len() > 4097 {
        return Err("invalid Compiler package record count".into());
    }
    let manifest: Manifest =
        serde_json::from_str(lines[0]).map_err(|e| format!("invalid Compiler manifest: {e}"))?;
    if manifest.schema != PACKAGE_SCHEMA
        || manifest.canonical_profile != "intelligence-lattice-canonical/v1"
        || manifest.event_count != lines.len() - 1
        || manifest.policy_digest != context.expected_policy_digest
        || manifest.task_id != context.expected_task_id
        || manifest.claim_id != context.expected_claim_id
    {
        return Err(
            "Compiler manifest does not match caller-pinned task, claim, policy, or event count"
                .into(),
        );
    }
    if manifest.task_event_id.is_empty()
        || !digest(&manifest.event_root)
        || manifest.policy.is_null()
    {
        return Err("Compiler manifest is missing required policy or provenance identity".into());
    }
    // Validate event lines are JSON and preserve their bytes; signature/identity
    // semantics belong to the pinned Compiler verifier, not this importer.
    for line in &lines[1..] {
        serde_json::from_str::<Value>(line).map_err(|e| format!("invalid event JSON: {e}"))?;
    }

    let report: ConformanceReport = serde_json::from_slice(report_bytes)
        .map_err(|e| format!("invalid Compiler report: {e}"))?;
    if report.schema != REPORT_SCHEMA
        || report.repository != COMPILER_REPOSITORY
        || report.revision != COMPILER_REVISION
        || report.evidence_class != "SYNTHETIC_SIGNED_INTEROPERABILITY_FIXTURE"
    {
        return Err(
            "Compiler report is not from the supported pinned synthetic conformance run".into(),
        );
    }
    let entry = report
        .catalog
        .iter()
        .find(|entry| entry.name == fixture_name)
        .ok_or("fixture absent from Compiler catalog")?;
    let native = &entry.native;
    let event_root = native
        .event_root
        .as_deref()
        .ok_or("Compiler report omitted event root")?;
    if !digest(event_root) || native.verifier_actor_ids.iter().any(|id| !digest(id)) {
        return Err("Compiler report contains invalid root or verifier identity".into());
    }
    if native.schema != "assurance-report/v1"
        || native.reason.is_empty()
        || native.package_digest != package_hash
        || native.task_id != manifest.task_id
        || native.claim_id != manifest.claim_id
        || native.event_count != manifest.event_count
        || native.code.is_empty()
        || native.limitations.is_empty()
        || report.canonical_probe.is_empty()
    {
        return Err("Compiler report does not bind this package".into());
    }
    Ok(CompilerImport {
        schema: "chimera-rchain-compiler-import/v1", status: "IMPORTED_NOT_OMEGA_VERIFIED",
        scope: "PINNED_COMPILER_REPORT_AND_PACKAGE_BINDING_ONLY", repository: COMPILER_REPOSITORY,
        revision: COMPILER_REVISION, fixture: fixture_name.to_owned(), package_digest: package_hash,
        compiler_status: native.status.clone(), compiler_code: native.code.clone(),
        task_id: native.task_id.clone(), claim_id: native.claim_id.clone(),
        policy_digest: manifest.policy_digest.clone(), event_count: manifest.event_count,
        event_root: event_root.to_owned(), verifier_actor_ids: native.verifier_actor_ids.clone(),
        operation: native.operation.clone(),
        limitations: vec![
            "The Compiler report is imported, not recomputed by OMEGA; rerun the pinned Compiler conformance command to establish its provenance.",
            "Distinct signing keys or verifier actor IDs do not establish independent people, machines, or organizations.",
            "Compiler PASS concerns registered verifier semantics; it does not establish external execution, production reachability, truth, or consensus/finality.",
        ],
    })
}
