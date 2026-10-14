//! Offline binding of selected captured audit files to a reviewer-pinned seal.
//! Raw capture bytes are opaque; a valid archive is not a reproduced finding.

use crate::encoding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const SOURCE_REPOSITORY: &str = "aixaria0/chimera-rchain-staking-audit";
pub const SOURCE_REVISION: &str = "ac839aa088ed66af726b53bb88be4d8d39cbd6a2";
pub const CONTEXT_DOMAIN: &str = "audit/archive-context/v1";
pub const MAX_ARTIFACTS: usize = 32;
pub const MAX_MANIFEST_FILES: usize = 64;
pub const MAX_FILE_BYTES: usize = 65_536;
pub const MAX_TOTAL_BYTES: usize = 524_288;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    RawObservation,
    DerivedInterpretation,
    Configuration,
    SourceDeclaration,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    NotApplicable,
    WalletNotification,
    DeployStatus,
    HostBlockCatalog,
    LivePos,
    LiveDelegations,
    NativePosRead,
    RecoveredState,
    ReplayReconstruction,
    PeerView,
    FinalizedHistory,
}

impl Surface {
    fn boundary(&self) -> &'static str {
        match self {
            Self::NotApplicable => "NO_DIRECT_OBSERVATION_CLAIM",
            Self::WalletNotification => "CLIENT_NOTIFICATION_ONLY",
            Self::DeployStatus => "INDEXED_HOST_BLOCK_EXECUTION_AND_REPLY_ONLY",
            Self::HostBlockCatalog => "QUERIED_NODE_BLOCK_CATALOG_ONLY",
            Self::LivePos => "QUERIED_NODE_LIVE_POS_VIEW_ONLY",
            Self::LiveDelegations => "QUERIED_NODE_LIVE_DELEGATION_VIEW_ONLY",
            Self::NativePosRead => "STATE_EXPOSED_AT_SELECTED_READ_ANCHOR_ONLY",
            Self::RecoveredState => "POST_RESTART_EXPOSED_STATE_ONLY",
            Self::ReplayReconstruction => "DECLARED_HISTORY_RECONSTRUCTION_ONLY",
            Self::PeerView => "SELECTED_PEER_LOCAL_VIEW_ONLY",
            Self::FinalizedHistory => "DECLARED_FINALIZED_HISTORY_WITNESS_ONLY",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub path: String,
    pub role: Role,
    pub surface: Surface,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    schema: String,
    source_repository: String,
    source_revision: String,
    archive_id: String,
    manifest_sha256: String,
    selection: Vec<Selection>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: String,
    content_chunks: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    schema: String,
    source_repository: String,
    source_revision: String,
    archive_id: String,
    manifest_chunks: Vec<String>,
    artifacts: Vec<Artifact>,
}

#[derive(Debug, Serialize)]
pub struct ArtifactBinding {
    pub path: String,
    pub sha256: String,
    pub byte_count: usize,
    pub reviewer_selected_role: Role,
    pub reviewer_selected_surface: Surface,
    pub declared_observer_boundary: &'static str,
    pub artifact_integrity: &'static str,
    pub observational_authenticity: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AuditArchiveReport {
    pub schema: &'static str,
    pub status: &'static str,
    pub scope: &'static str,
    pub source_repository: &'static str,
    pub source_revision: &'static str,
    pub archive_id: String,
    pub context_digest: String,
    pub manifest_sha256: String,
    pub manifest_file_count: usize,
    pub selected_file_count: usize,
    pub selected_byte_count: usize,
    pub archive_coverage: &'static str,
    pub unavailable_artifacts: Vec<String>,
    pub manifest_binding: &'static str,
    pub reviewer_role_binding: &'static str,
    pub artifacts: Vec<ArtifactBinding>,
    pub source_execution_authenticity: &'static str,
    pub independent_observation: &'static str,
    pub external_archive_anchor: &'static str,
    pub production_impact: &'static str,
    pub consensus_finality: &'static str,
    pub finding_verdict: &'static str,
    pub target_execution: &'static str,
    pub omega_core_verdict: &'static str,
    pub limitations: Vec<&'static str>,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 128
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn join_chunks(chunks: &[String], limit: usize) -> Result<String, String> {
    if chunks.is_empty() || chunks.len() > 32 {
        return Err("invalid content chunk count".into());
    }
    if chunks.iter().any(|s| s.len() > 4096) {
        return Err("content chunk exceeds 4096 bytes".into());
    }
    let length: usize = chunks.iter().map(String::len).sum();
    if length > limit {
        return Err("decoded content exceeds byte limit".into());
    }
    Ok(chunks.concat())
}

fn parse_manifest(text: &str) -> Result<BTreeMap<String, String>, String> {
    if text.is_empty() || !text.ends_with('\n') || text.contains('\r') {
        return Err("manifest must be nonempty and LF terminated".into());
    }
    let mut result = BTreeMap::new();
    let mut prior = "";
    for line in text
        .strip_suffix('\n')
        .ok_or("missing final LF")?
        .split('\n')
    {
        let (hash, path) = line.split_once("  ").ok_or("invalid manifest delimiter")?;
        if !encoding::is_digest(hash)
            || !valid_path(path)
            || path == "manifest.sha256"
            || path <= prior
        {
            return Err("invalid, duplicate, or unordered manifest entry".into());
        }
        result.insert(path.to_owned(), hash.to_owned());
        prior = path;
        if result.len() > MAX_MANIFEST_FILES {
            return Err("manifest exceeds 64 files".into());
        }
    }
    Ok(result)
}

/// `expected_context` must come from an independently reviewed trust selection.
/// Producer-supplied context files and their own digests are not trust anchors.
pub fn verify_audit_archive(
    archive_bytes: &[u8],
    context_bytes: &[u8],
    expected_context: &str,
) -> Result<AuditArchiveReport, String> {
    let context_value = encoding::parse(context_bytes)?;
    let context_digest = encoding::digest(CONTEXT_DOMAIN, &context_value)?;
    if !encoding::is_digest(expected_context) || context_digest != expected_context {
        return Err("reviewer-pinned audit context digest mismatch".into());
    }
    let context: Context = serde_json::from_value(context_value).map_err(|e| e.to_string())?;
    if context.schema != "chimera-audit-archive-context/v1"
        || context.source_repository != SOURCE_REPOSITORY
        || context.source_revision != SOURCE_REVISION
        || !valid_path(&context.archive_id)
        || !encoding::is_digest(&context.manifest_sha256)
        || context.selection.is_empty()
        || context.selection.len() > MAX_ARTIFACTS
    {
        return Err("unsupported or invalid audit context".into());
    }
    let mut prior = "";
    for selected in &context.selection {
        if !valid_path(&selected.path)
            || selected.path.as_str() <= prior
            || (selected.role == Role::RawObservation)
                == (selected.surface == Surface::NotApplicable)
        {
            return Err("invalid reviewer selection or observer role".into());
        }
        prior = &selected.path;
    }
    let archive: Archive =
        serde_json::from_value(encoding::parse(archive_bytes)?).map_err(|e| e.to_string())?;
    if archive.schema != "chimera-audit-archive/v1"
        || archive.source_repository != context.source_repository
        || archive.source_revision != context.source_revision
        || archive.archive_id != context.archive_id
        || archive.artifacts.len() != context.selection.len()
    {
        return Err("archive does not match reviewer-selected identity or file count".into());
    }
    let manifest_text = join_chunks(&archive.manifest_chunks, 16_384)?;
    if sha256(manifest_text.as_bytes()) != context.manifest_sha256 {
        return Err("reviewer-pinned manifest digest mismatch".into());
    }
    let manifest = parse_manifest(&manifest_text)?;
    let mut files = BTreeMap::new();
    let mut selected_byte_count = 0usize;
    for artifact in archive.artifacts {
        if !valid_path(&artifact.path) || files.contains_key(&artifact.path) {
            return Err("invalid or duplicate artifact path".into());
        }
        let content = join_chunks(&artifact.content_chunks, MAX_FILE_BYTES)?;
        selected_byte_count += content.len();
        if selected_byte_count > MAX_TOTAL_BYTES {
            return Err("selected content exceeds 512 KiB".into());
        }
        let digest = sha256(content.as_bytes());
        if manifest.get(&artifact.path) != Some(&digest) {
            return Err(format!(
                "artifact bytes do not match sealed manifest: {}",
                artifact.path
            ));
        }
        files.insert(artifact.path, (digest, content.len()));
    }
    let mut artifacts = Vec::new();
    for selected in context.selection {
        let (digest, byte_count) = files
            .remove(&selected.path)
            .ok_or("selected artifact missing")?;
        artifacts.push(ArtifactBinding {
            path: selected.path,
            sha256: digest,
            byte_count,
            declared_observer_boundary: selected.surface.boundary(),
            reviewer_selected_role: selected.role,
            reviewer_selected_surface: selected.surface,
            artifact_integrity: "CONFIRMED",
            observational_authenticity: "UNKNOWN",
        });
    }
    if !files.is_empty() {
        return Err("unselected artifacts supplied".into());
    }
    let unavailable_artifacts: Vec<_> = manifest
        .keys()
        .filter(|path| !artifacts.iter().any(|a| &a.path == *path))
        .cloned()
        .collect();
    Ok(AuditArchiveReport {
        schema: "chimera-audit-archive-binding/v1", status: "ARCHIVE_BINDING_CONFIRMED",
        scope: "PINNED_ARCHIVE_BYTES_AND_REVIEWER_SELECTED_ROLES_ONLY",
        source_repository: SOURCE_REPOSITORY, source_revision: SOURCE_REVISION,
        archive_id: context.archive_id, context_digest, manifest_sha256: context.manifest_sha256,
        manifest_file_count: manifest.len(), selected_file_count: artifacts.len(), selected_byte_count,
        archive_coverage: if unavailable_artifacts.is_empty() { "ALL_MANIFEST_FILES" } else { "SELECTED_MANIFEST_FILES_ONLY" },
        unavailable_artifacts, manifest_binding: "CONFIRMED", reviewer_role_binding: "CONFIRMED", artifacts,
        source_execution_authenticity: "UNKNOWN", independent_observation: "UNKNOWN",
        external_archive_anchor: "UNKNOWN", production_impact: "UNKNOWN", consensus_finality: "UNKNOWN",
        finding_verdict: "NOT_RUN", target_execution: "NOT_RUN", omega_core_verdict: "NOT_RUN",
        limitations: vec![
            "The external context pin selects authority; the producer cannot establish trust by supplying its own pin.",
            "Content hashes preserve reviewed bytes, not the authenticity or completeness of an observed execution.",
            "Raw captures, interpretations, configuration, and source declarations retain separate reviewer-selected roles.",
            "Observer boundaries are declared scopes; even a finalized-history label does not prove finality.",
            "Unavailable manifest files are explicit; files outside the selected manifest are not assessed.",
            "No source code or deployment is executed, and no archived finding or production impact is independently reproduced.",
        ],
    })
}
