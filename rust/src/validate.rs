use crate::encoding::is_digest;
use crate::model::*;
use std::collections::{BTreeMap, BTreeSet};

fn id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("invalid identifier".into());
    }
    Ok(())
}

fn text(value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 4096 {
        return Err("empty or oversized text".into());
    }
    Ok(())
}

fn unique(values: &[String]) -> Result<(), String> {
    if values.len() > 256 {
        return Err("reference list exceeds 256 entries".into());
    }
    let mut seen = BTreeSet::new();
    for value in values {
        id(value)?;
        if !seen.insert(value) {
            return Err(format!("duplicate reference: {value}"));
        }
    }
    Ok(())
}

pub(crate) fn validate(envelope: &Envelope) -> Result<Vec<String>, String> {
    if envelope.schema != ENVELOPE_SCHEMA || envelope.claim.schema != CLAIM_SCHEMA {
        return Err("unsupported envelope or claim schema".into());
    }
    if envelope.policy != POLICY {
        return Err("unsupported verification policy".into());
    }
    let claim = &envelope.claim;
    id(&claim.id)?;
    text(&claim.statement)?;
    text(&claim.target.system)?;
    text(&claim.target.revision)?;
    if !is_digest(&claim.target.configuration) || !is_digest(&claim.target.environment) {
        return Err("configuration and environment must be SHA-256 identities".into());
    }
    if claim.assumptions.len() > 64 || claim.limitations.is_empty() || claim.limitations.len() > 64
    {
        return Err("bounded assumptions and at least one limitation are required".into());
    }
    for item in claim.assumptions.iter().chain(&claim.limitations) {
        text(item)?;
    }
    if envelope.evidence.len() > 256 {
        return Err("evidence exceeds 256 nodes".into());
    }
    let mut nodes = BTreeMap::new();
    for node in &envelope.evidence {
        let body = &node.body;
        if body.schema != NODE_SCHEMA {
            return Err("unsupported evidence schema".into());
        }
        id(&body.id)?;
        id(&body.producer.id)?;
        unique(&body.parents)?;
        if !is_digest(&body.claim_digest) || !is_digest(&node.digest) {
            return Err("malformed evidence digest".into());
        }
        if nodes.insert(body.id.as_str(), body).is_some() {
            return Err(format!("duplicate evidence id: {}", body.id));
        }
        match &body.payload {
            Payload::StateTrace { states } => {
                if states.is_empty() || states.len() > 2048 || !states.iter().all(|s| is_digest(s))
                {
                    return Err("traces require 1..2048 state digests".into());
                }
            }
            Payload::MutationControl {
                baseline,
                index,
                replacement,
            } => {
                id(baseline)?;
                if *index >= 2048 || !is_digest(replacement) {
                    return Err("invalid mutation control".into());
                }
                if !matches!(body.evidence_class, EvidenceClass::Synthetic) {
                    return Err("mutation controls must remain synthetic".into());
                }
                if !body.parents.contains(baseline) {
                    return Err("control missing baseline provenance".into());
                }
            }
        }
    }

    // Validate and sort the entire graph, including nodes not yet assigned a role.
    let mut degrees = BTreeMap::new();
    let mut ready = BTreeSet::new();
    for (&name, body) in &nodes {
        for parent in &body.parents {
            if !nodes.contains_key(parent.as_str()) {
                return Err(format!("dangling provenance: {parent}"));
            }
        }
        degrees.insert(name, body.parents.len());
        if body.parents.is_empty() {
            ready.insert(name);
        }
    }
    let mut order = Vec::new();
    while let Some(name) = ready.pop_first() {
        order.push(name.to_string());
        for (&child, body) in &nodes {
            if body.parents.iter().any(|p| p == name) {
                let degree = degrees.get_mut(child).ok_or("missing graph degree")?;
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(child);
                }
            }
        }
    }
    if order.len() != nodes.len() {
        return Err("provenance cycle".into());
    }

    let predicate = &claim.predicate;
    id(&predicate.expected)?;
    unique(&predicate.observed)?;
    unique(&predicate.negative_controls)?;
    let mut roles = BTreeSet::new();
    for reference in std::iter::once(&predicate.expected)
        .chain(&predicate.observed)
        .chain(&predicate.negative_controls)
    {
        if !roles.insert(reference.as_str()) {
            return Err("evidence roles must be disjoint".into());
        }
        if !nodes.contains_key(reference.as_str()) {
            return Err(format!("missing required evidence: {reference}"));
        }
    }
    if roles.len() != nodes.len() {
        return Err("unassigned evidence is forbidden; every observation must be evaluated".into());
    }
    for reference in std::iter::once(&predicate.expected).chain(&predicate.observed) {
        if !matches!(
            nodes[reference.as_str()].payload,
            Payload::StateTrace { .. }
        ) {
            return Err("trace role requires state_trace".into());
        }
    }
    for reference in &predicate.negative_controls {
        match &nodes[reference.as_str()].payload {
            Payload::MutationControl {
                baseline, index, ..
            } => {
                if !predicate.observed.contains(baseline) {
                    return Err("control baseline is not an observation".into());
                }
                if let Payload::StateTrace { states } = &nodes[baseline.as_str()].payload {
                    if *index >= states.len() {
                        return Err("control index outside baseline trace".into());
                    }
                }
            }
            _ => return Err("control role requires mutation_control".into()),
        }
    }
    Ok(order)
}
