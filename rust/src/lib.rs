#![forbid(unsafe_code)]

pub mod adapter;
pub mod aether;
pub mod aether_historical;
pub mod aether_journal;
pub mod aether_lattice;
pub mod audit_archive;
pub mod compiler;
pub mod encoding;
pub mod model;
pub mod observer;
mod validate;
mod verify;
pub mod witness;

pub use verify::{first_divergence, verify};

use model::*;
use serde_json::Value;

fn normalized(mut envelope: Envelope) -> Envelope {
    envelope.claim.predicate.observed.sort();
    envelope.claim.predicate.negative_controls.sort();
    for node in &mut envelope.evidence {
        node.body.parents.sort();
    }
    envelope.evidence.sort_by(|a, b| a.body.id.cmp(&b.body.id));
    envelope
}

fn value<T: serde::Serialize>(value: &T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|e| e.to_string())
}

fn envelope_digest(envelope: &Envelope) -> Result<String, String> {
    let mut body = value(envelope)?;
    body.as_object_mut()
        .ok_or("envelope must be an object")?
        .remove("digest");
    encoding::digest("envelope/v2", &body)
}

/// Authoring only: recomputes bindings and content addresses. Does not establish truth.
/// All schema/graph constraints are checked, but semantic contradictions remain sealable.
pub fn seal(input: &[u8]) -> Result<Envelope, String> {
    let mut envelope =
        normalized(serde_json::from_value(encoding::parse(input)?).map_err(|e| e.to_string())?);
    let claim_digest = encoding::digest("claim/v2", &value(&envelope.claim)?)?;
    for node in &mut envelope.evidence {
        node.body.claim_digest = claim_digest.clone();
        node.digest = encoding::digest("evidence-node/v1", &value(&node.body)?)?;
    }
    envelope.digest = envelope_digest(&envelope)?;
    validate::validate(&envelope)?;
    if serde_json::to_vec_pretty(&envelope)
        .map_err(|e| e.to_string())?
        .len()
        + 1
        > encoding::MAX_BYTES
    {
        return Err("sealed package exceeds 1 MiB".into());
    }
    Ok(envelope)
}
