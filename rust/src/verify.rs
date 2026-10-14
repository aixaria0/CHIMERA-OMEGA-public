use crate::{encoding, envelope_digest, model::*, normalized, validate, value};
use std::collections::{BTreeMap, BTreeSet};

/// Earliest unequal state commitment, including missing/extra suffixes.
/// This identifies an artifact index, not the cause of a target-system failure.
pub fn first_divergence(expected: &[String], observed: &[String]) -> Option<Divergence> {
    for index in 0..expected.len().max(observed.len()) {
        if expected.get(index) != observed.get(index) {
            return Some(Divergence {
                index,
                previous: index.checked_sub(1).and_then(|i| expected.get(i)).cloned(),
                expected: expected.get(index).cloned(),
                observed: observed.get(index).cloned(),
            });
        }
    }
    None
}

fn trace(body: &EvidenceBody) -> Result<&[String], String> {
    match &body.payload {
        Payload::StateTrace { states } => Ok(states),
        _ => Err("expected a state trace".into()),
    }
}

/// The pin must come from the caller's expected artifact, not from the untrusted package.
/// Neither a pin nor a valid digest authenticates a producer or proves external truth.
pub fn verify(input: &[u8], expected_digest: &str) -> Result<Report, String> {
    if !encoding::is_digest(expected_digest) {
        return Err("a caller-supplied envelope digest pin is required".into());
    }
    let envelope: Envelope =
        serde_json::from_value(encoding::parse(input)?).map_err(|e| e.to_string())?;
    let envelope = normalized(envelope);
    let order = validate::validate(&envelope)?;
    let claim_digest = encoding::digest("claim/v2", &value(&envelope.claim)?)?;
    for node in &envelope.evidence {
        if node.body.claim_digest != claim_digest {
            return Err(format!("claim/target binding mismatch: {}", node.body.id));
        }
        if node.digest != encoding::digest("evidence-node/v1", &value(&node.body)?)? {
            return Err(format!("evidence digest mismatch: {}", node.body.id));
        }
    }
    let digest = envelope_digest(&envelope)?;
    if envelope.digest != digest {
        return Err("envelope digest mismatch".into());
    }
    if expected_digest != digest {
        return Err("caller pin mismatch".into());
    }

    let nodes: BTreeMap<_, _> = envelope
        .evidence
        .iter()
        .map(|n| (n.body.id.as_str(), &n.body))
        .collect();
    let predicate = &envelope.claim.predicate;
    let expected = trace(nodes[predicate.expected.as_str()])?;
    let mut comparisons = Vec::new();
    for reference in &predicate.observed {
        let divergence = first_divergence(expected, trace(nodes[reference.as_str()])?);
        comparisons.push(Comparison {
            evidence_id: reference.clone(),
            state: if divergence.is_some() {
                State::Contradicted
            } else {
                State::Confirmed
            },
            first_divergence: divergence,
        });
    }

    let mut controls = Vec::new();
    let mut controlled = BTreeSet::new();
    for reference in &predicate.negative_controls {
        if let Payload::MutationControl {
            baseline,
            index,
            replacement,
        } = &nodes[reference.as_str()].payload
        {
            let original = trace(nodes[baseline.as_str()])?;
            let (state, reason, divergence) = if first_divergence(expected, original).is_some() {
                (
                    State::NotRun,
                    "baseline already contradicts predicate",
                    None,
                )
            } else {
                let mut mutated = original.to_vec();
                mutated[*index] = replacement.clone();
                let divergence = first_divergence(expected, &mutated);
                if divergence.is_some() {
                    controlled.insert(baseline.as_str());
                    (
                        State::Pass,
                        "same comparison procedure rejected the deterministic mutation",
                        divergence,
                    )
                } else {
                    (
                        State::Fail,
                        "control did not falsify predicate (no-op mutation)",
                        None,
                    )
                }
            };
            controls.push(ControlResult {
                evidence_id: reference.clone(),
                baseline: baseline.clone(),
                state,
                reason: reason.into(),
                first_divergence: divergence,
            });
        }
    }
    let conformance = if comparisons.iter().any(|c| c.state == State::Contradicted) {
        State::Contradicted
    } else if comparisons.is_empty() {
        State::Unknown
    } else {
        State::Confirmed
    };
    let negative = if controls.iter().any(|c| c.state == State::Fail) {
        State::Fail
    } else if comparisons.is_empty() || controlled.len() != comparisons.len() {
        State::NotRun
    } else {
        State::Pass
    };
    let status = match (conformance, negative) {
        (State::Contradicted, _) => Overall::Contradicted,
        (State::Confirmed, State::Pass) => Overall::LocallySupported,
        _ => Overall::Inconclusive,
    };
    let mut reasons = vec!["Only equality of supplied state-digest sequences is evaluated; target execution is not performed.".into()];
    if negative != State::Pass {
        reasons.push("Every observation requires a successful mutation control; missing or failed coverage blocks local support.".into());
    }
    if conformance == State::Contradicted {
        reasons.push("At least one supplied observation contradicts the expected trace; no majority rule hides it.".into());
    }
    let mut limitations = envelope.claim.limitations.clone();
    limitations.extend([
        "Producer IDs and evidence classes are declarations, not authenticated identities or independent observations.".into(),
        "State commitments are compared; referenced raw state bytes are not fetched or verified.".into(),
        "Synthetic mutation controls test this equality predicate, not the target or the entire verifier.".into(),
    ]);
    Ok(Report {
        schema: "chimera-verification-report/v2".into(),
        policy: envelope.policy,
        claim_id: envelope.claim.id,
        envelope_digest: digest,
        claim_digest,
        status,
        scope: "PINNED_ARTIFACT_TRACE_EQUALITY_ONLY".into(),
        dimensions: Dimensions {
            artifact_conformance: conformance,
            negative_control: negative,
            formal_proof: State::Unknown,
            implementation_binding: State::Unknown,
            runtime_reproduction: State::Unknown,
            independent_observation: State::Unknown,
            replay: State::NotRun,
            production_reachability: State::Unknown,
            finality_externality: State::Unknown,
        },
        provenance_order: order,
        comparisons,
        controls,
        assumptions: envelope.claim.assumptions,
        limitations,
        reasons,
    })
}
