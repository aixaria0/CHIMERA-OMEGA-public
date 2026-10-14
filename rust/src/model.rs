use serde::{Deserialize, Serialize};

pub const ENVELOPE_SCHEMA: &str = "chimera-evidence-envelope/v2";
pub const CLAIM_SCHEMA: &str = "chimera-claim/v2";
pub const NODE_SCHEMA: &str = "chimera-evidence-node/v1";
pub const POLICY: &str = "omega.trace-equality/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub schema: String,
    pub policy: String,
    pub claim: Claim,
    pub evidence: Vec<EvidenceNode>,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub schema: String,
    pub id: String,
    pub statement: String,
    pub epistemic_state: EpistemicState,
    pub target: Target,
    pub assumptions: Vec<String>,
    pub limitations: Vec<String>,
    pub predicate: TraceEquality,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EpistemicState {
    Proposal,
    Hypothesis,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub system: String,
    pub revision: String,
    pub configuration: String,
    pub environment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceEquality {
    pub kind: PredicateKind,
    pub expected: String,
    pub observed: Vec<String>,
    pub negative_controls: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PredicateKind {
    #[serde(rename = "trace_equality")]
    TraceEquality,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceNode {
    pub body: EvidenceBody,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBody {
    pub schema: String,
    pub id: String,
    pub claim_digest: String,
    pub parents: Vec<String>,
    pub evidence_class: EvidenceClass,
    pub producer: Producer,
    pub payload: Payload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceClass {
    Synthetic,
    Recorded,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Producer {
    pub id: String,
    pub kind: ProducerKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProducerKind {
    Human,
    Program,
    Ai,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Payload {
    StateTrace {
        states: Vec<String>,
    },
    MutationControl {
        baseline: String,
        index: usize,
        replacement: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum State {
    Unknown,
    NotApplicable,
    NotRun,
    Confirmed,
    Contradicted,
    Pass,
    Fail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Overall {
    LocallySupported,
    Inconclusive,
    Contradicted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Divergence {
    pub index: usize,
    pub previous: Option<String>,
    pub expected: Option<String>,
    pub observed: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Comparison {
    pub evidence_id: String,
    pub state: State,
    pub first_divergence: Option<Divergence>,
}

#[derive(Debug, Serialize)]
pub struct ControlResult {
    pub evidence_id: String,
    pub baseline: String,
    pub state: State,
    pub reason: String,
    pub first_divergence: Option<Divergence>,
}

#[derive(Debug, Serialize)]
pub struct Dimensions {
    pub artifact_conformance: State,
    pub formal_proof: State,
    pub implementation_binding: State,
    pub runtime_reproduction: State,
    pub independent_observation: State,
    pub replay: State,
    pub negative_control: State,
    pub production_reachability: State,
    pub finality_externality: State,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: String,
    pub policy: String,
    pub claim_id: String,
    pub envelope_digest: String,
    pub claim_digest: String,
    pub status: Overall,
    pub scope: String,
    pub dimensions: Dimensions,
    pub provenance_order: Vec<String>,
    pub comparisons: Vec<Comparison>,
    pub controls: Vec<ControlResult>,
    pub assumptions: Vec<String>,
    pub limitations: Vec<String>,
    pub reasons: Vec<String>,
}
