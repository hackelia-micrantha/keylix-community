//! Bounded, non-authoritative AI-assisted adversarial test discovery.
//!
//! Model-facing JSON is validated by the manual adapter. This module accepts a
//! smaller canonical mutation record and remains the deterministic protocol
//! oracle. No model output can provide keys, proofs, tokens, nonces, or expected
//! results.

use std::collections::HashSet;
use std::fmt;

use keylix_dpop::{
    AwsLcP256Signer, Clock, DpopError, DpopNonce, DpopPortError, DpopProofBuilder, DpopRequest,
    DpopVerifier, EffectiveRequestTarget, InMemoryReplayStore, RandomProofIdGenerator,
    UnverifiedDpopProof, VerificationPolicy,
};

/// Maximum candidates accepted from one model invocation.
pub const MAX_CANDIDATES: usize = 16;
/// Maximum candidate identifier length.
pub const MAX_ID_BYTES: usize = 64;

/// Provider-neutral candidate batch after model-facing schema validation.
#[derive(Debug)]
pub struct CandidateBatch {
    candidates: Vec<Candidate>,
}

/// One canonical semantic adversarial candidate.
#[derive(Debug)]
pub struct Candidate {
    id: String,
    mutation: MutationKind,
}

/// Closed semantic mutation vocabulary available to model-assisted discovery.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum MutationKind {
    /// Verify a proof against a different HTTP method.
    MethodMismatch,
    /// Verify a proof against a different effective request target.
    TargetMismatch,
    /// Change query ordering while preserving the normalized `DPoP` target.
    QueryVariationIgnored,
    /// Verify a protected-resource proof against a different token byte string.
    AccessTokenMismatch,
    /// Verify a nonce-bound proof against a different nonce.
    NonceMismatch,
    /// Submit the exact same proof twice in one replay scope.
    ReplaySameProof,
}

impl MutationKind {
    /// Parse one exact schema vocabulary value.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is not in the closed mutation vocabulary.
    pub fn from_schema_value(value: &str) -> Result<Self, AiAdversaryError> {
        match value {
            "method_mismatch" => Ok(Self::MethodMismatch),
            "target_mismatch" => Ok(Self::TargetMismatch),
            "query_variation_ignored" => Ok(Self::QueryVariationIgnored),
            "access_token_mismatch" => Ok(Self::AccessTokenMismatch),
            "nonce_mismatch" => Ok(Self::NonceMismatch),
            "replay_same_proof" => Ok(Self::ReplaySameProof),
            _ => Err(error("unsupported semantic mutation")),
        }
    }

    /// Return whether the semantic dimension already had explicit deterministic
    /// coverage before the initial AI-assisted discovery experiment.
    #[must_use]
    pub const fn previously_covered(self) -> bool {
        !matches!(self, Self::QueryVariationIgnored)
    }
}

/// Deterministically observed protocol outcome.
#[derive(Debug, PartialEq, Eq)]
pub enum ObservedOutcome {
    /// Verification succeeded as required by the deterministic contract.
    Verified,
    /// Verification rejected the candidate with the given protocol error.
    Rejected(DpopError),
}

/// Deterministic evaluation result for one model-proposed mutation.
#[derive(Debug, PartialEq, Eq)]
pub struct Evaluation {
    /// Candidate identifier copied from the validated input.
    pub id: String,
    /// Evaluated semantic mutation.
    pub mutation: MutationKind,
    /// Exact Keylix outcome observed by deterministic verification.
    pub observed: ObservedOutcome,
    /// Whether this mutation represents a semantic dimension absent from the
    /// pre-experiment deterministic inventory.
    pub novel_dimension: bool,
}

/// Fail-closed error returned for invalid candidate data or evaluator failure.
#[derive(Debug)]
pub struct AiAdversaryError(String);

impl fmt::Display for AiAdversaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AiAdversaryError {}

impl CandidateBatch {
    /// Parse the adapter's canonical `id<TAB>mutation` records.
    ///
    /// Blank lines, extra fields, duplicate IDs, duplicate mutations, invalid
    /// identifiers, unsupported mutations, and over-sized batches fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error when any record is malformed, an identifier or mutation
    /// is invalid, candidates are duplicated, or the batch count is out of bounds.
    pub fn parse_canonical(input: &str) -> Result<Self, AiAdversaryError> {
        let mut candidates = Vec::new();
        for line in input.lines() {
            if line.is_empty() {
                return Err(error("blank canonical candidate record"));
            }
            let mut fields = line.split('\t');
            let id = fields
                .next()
                .ok_or_else(|| error("candidate identifier missing"))?;
            let mutation = fields
                .next()
                .ok_or_else(|| error("candidate mutation missing"))?;
            if fields.next().is_some() {
                return Err(error("canonical candidate record has extra fields"));
            }
            validate_identifier(id)?;
            candidates.push(Candidate {
                id: id.to_owned(),
                mutation: MutationKind::from_schema_value(mutation)?,
            });
        }

        let batch = Self { candidates };
        batch.validate()?;
        Ok(batch)
    }

    /// Validate count and duplicate invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized batch, an invalid identifier,
    /// or duplicate candidate identifiers or semantic mutations.
    pub fn validate(&self) -> Result<(), AiAdversaryError> {
        if self.candidates.is_empty() || self.candidates.len() > MAX_CANDIDATES {
            return Err(error("candidate count is outside the accepted bounds"));
        }

        let mut ids = HashSet::with_capacity(self.candidates.len());
        let mut mutations = HashSet::with_capacity(self.candidates.len());
        for candidate in &self.candidates {
            validate_identifier(&candidate.id)?;
            if !ids.insert(candidate.id.as_str()) {
                return Err(error("duplicate candidate identifier"));
            }
            if !mutations.insert(candidate.mutation) {
                return Err(error("duplicate semantic mutation"));
            }
        }
        Ok(())
    }

    /// Evaluate every candidate using synthetic local protocol material.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails, local protocol material cannot be
    /// constructed, or deterministic verification differs from the contract for
    /// the selected semantic mutation.
    pub fn evaluate(&self) -> Result<Vec<Evaluation>, AiAdversaryError> {
        self.validate()?;
        self.candidates.iter().map(evaluate_candidate).collect()
    }
}

fn evaluate_candidate(candidate: &Candidate) -> Result<Evaluation, AiAdversaryError> {
    let observed = match candidate.mutation {
        MutationKind::MethodMismatch => evaluate_method_mismatch()?,
        MutationKind::TargetMismatch => evaluate_target_mismatch()?,
        MutationKind::QueryVariationIgnored => evaluate_query_variation_ignored()?,
        MutationKind::AccessTokenMismatch => evaluate_access_token_mismatch()?,
        MutationKind::NonceMismatch => evaluate_nonce_mismatch()?,
        MutationKind::ReplaySameProof => evaluate_replay()?,
    };

    Ok(Evaluation {
        id: candidate.id.clone(),
        mutation: candidate.mutation,
        observed,
        novel_dimension: !candidate.mutation.previously_covered(),
    })
}

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> Result<i64, DpopPortError> {
        Ok(self.0)
    }
}

fn build_proof(request: &DpopRequest<'_>) -> Result<String, AiAdversaryError> {
    let signer = AwsLcP256Signer::generate().map_err(protocol_error)?;
    let clock = FixedClock(1_700_000_000);
    let proof = DpopProofBuilder::new(&signer, &clock, &RandomProofIdGenerator)
        .build(request)
        .map_err(protocol_error)?;
    Ok(proof.as_header_value().to_owned())
}

fn verify(
    proof: &str,
    request: &DpopRequest<'_>,
) -> Result<Result<(), DpopError>, AiAdversaryError> {
    let clock = FixedClock(1_700_000_000);
    let parsed = UnverifiedDpopProof::parse(proof).map_err(protocol_error)?;
    let replay = InMemoryReplayStore::new(clock, 8).map_err(protocol_error)?;
    Ok(DpopVerifier::new(&clock, VerificationPolicy::default())
        .verify(&parsed, request, &replay)
        .map(|_| ()))
}

fn evaluate_method_mismatch() -> Result<ObservedOutcome, AiAdversaryError> {
    let target = EffectiveRequestTarget::parse("https://api.example.test/resource")
        .map_err(protocol_error)?;
    let proof_request = DpopRequest::new("GET", &target).map_err(protocol_error)?;
    let proof = build_proof(&proof_request)?;
    let verification_request = DpopRequest::new("POST", &target).map_err(protocol_error)?;
    expect_rejection(&proof, &verification_request, DpopError::MethodMismatch)
}

fn evaluate_target_mismatch() -> Result<ObservedOutcome, AiAdversaryError> {
    let proof_target = EffectiveRequestTarget::parse("https://api.example.test/resource")
        .map_err(protocol_error)?;
    let other_target =
        EffectiveRequestTarget::parse("https://api.example.test/other").map_err(protocol_error)?;
    let proof_request = DpopRequest::new("GET", &proof_target).map_err(protocol_error)?;
    let proof = build_proof(&proof_request)?;
    let verification_request = DpopRequest::new("GET", &other_target).map_err(protocol_error)?;
    expect_rejection(&proof, &verification_request, DpopError::TargetMismatch)
}

fn evaluate_query_variation_ignored() -> Result<ObservedOutcome, AiAdversaryError> {
    let proof_target = EffectiveRequestTarget::parse("https://api.example.test/resource?a=1&b=2")
        .map_err(protocol_error)?;
    let reordered = EffectiveRequestTarget::parse("https://api.example.test/resource?b=2&a=1")
        .map_err(protocol_error)?;
    let proof_request = DpopRequest::new("GET", &proof_target).map_err(protocol_error)?;
    let proof = build_proof(&proof_request)?;
    let verification_request = DpopRequest::new("GET", &reordered).map_err(protocol_error)?;
    expect_verification(&proof, &verification_request)
}

fn evaluate_access_token_mismatch() -> Result<ObservedOutcome, AiAdversaryError> {
    let target = EffectiveRequestTarget::parse("https://api.example.test/resource")
        .map_err(protocol_error)?;
    let proof_request = DpopRequest::new("GET", &target)
        .map_err(protocol_error)?
        .with_access_token(b"synthetic-token-a");
    let proof = build_proof(&proof_request)?;
    let verification_request = DpopRequest::new("GET", &target)
        .map_err(protocol_error)?
        .with_access_token(b"synthetic-token-b");
    expect_rejection(
        &proof,
        &verification_request,
        DpopError::AccessTokenHashMismatch,
    )
}

fn evaluate_nonce_mismatch() -> Result<ObservedOutcome, AiAdversaryError> {
    let target = EffectiveRequestTarget::parse("https://api.example.test/resource")
        .map_err(protocol_error)?;
    let proof_nonce = DpopNonce::new("synthetic-nonce-a").map_err(protocol_error)?;
    let other_nonce = DpopNonce::new("synthetic-nonce-b").map_err(protocol_error)?;
    let proof_request = DpopRequest::new("GET", &target)
        .map_err(protocol_error)?
        .with_nonce(&proof_nonce);
    let proof = build_proof(&proof_request)?;
    let verification_request = DpopRequest::new("GET", &target)
        .map_err(protocol_error)?
        .with_nonce(&other_nonce);
    expect_rejection(&proof, &verification_request, DpopError::NonceMismatch)
}

fn evaluate_replay() -> Result<ObservedOutcome, AiAdversaryError> {
    let target = EffectiveRequestTarget::parse("https://api.example.test/resource")
        .map_err(protocol_error)?;
    let request = DpopRequest::new("GET", &target).map_err(protocol_error)?;
    let proof = build_proof(&request)?;
    let clock = FixedClock(1_700_000_000);
    let parsed = UnverifiedDpopProof::parse(&proof).map_err(protocol_error)?;
    let replay = InMemoryReplayStore::new(clock, 8).map_err(protocol_error)?;
    let verifier = DpopVerifier::new(&clock, VerificationPolicy::default());
    verifier
        .verify(&parsed, &request, &replay)
        .map_err(protocol_error)?;
    match verifier.verify(&parsed, &request, &replay) {
        Err(DpopError::ReplayDetected) => Ok(ObservedOutcome::Rejected(DpopError::ReplayDetected)),
        Err(other) => Err(error(format!(
            "expected replay detection but observed {other}"
        ))),
        Ok(_) => Err(error("replayed proof unexpectedly verified")),
    }
}

fn expect_rejection(
    proof: &str,
    request: &DpopRequest<'_>,
    expected: DpopError,
) -> Result<ObservedOutcome, AiAdversaryError> {
    match verify(proof, request)? {
        Err(observed) if observed == expected => Ok(ObservedOutcome::Rejected(observed)),
        Err(observed) => Err(error(format!(
            "expected {expected} but observed {observed}"
        ))),
        Ok(()) => Err(error("adversarial candidate unexpectedly verified")),
    }
}

fn expect_verification(
    proof: &str,
    request: &DpopRequest<'_>,
) -> Result<ObservedOutcome, AiAdversaryError> {
    match verify(proof, request)? {
        Ok(()) => Ok(ObservedOutcome::Verified),
        Err(observed) => Err(error(format!(
            "candidate unexpectedly rejected with {observed}"
        ))),
    }
}

fn validate_identifier(id: &str) -> Result<(), AiAdversaryError> {
    if id.is_empty() || id.len() > MAX_ID_BYTES {
        return Err(error("candidate identifier is outside the accepted bounds"));
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(error(
            "candidate identifier contains unsupported characters",
        ));
    }
    Ok(())
}

fn protocol_error(error_value: impl fmt::Display) -> AiAdversaryError {
    error(format!("deterministic evaluator failure: {error_value}"))
}

fn error(message: impl Into<String>) -> AiAdversaryError {
    AiAdversaryError(message.into())
}

#[cfg(test)]
mod tests {
    use super::{CandidateBatch, DpopError, MutationKind, ObservedOutcome};

    #[test]
    fn canonical_input_rejects_duplicates_unknown_mutations_and_extra_fields() {
        assert!(CandidateBatch::parse_canonical("a\tmethod_mismatch\textra").is_err());
        assert!(CandidateBatch::parse_canonical("a\tunknown").is_err());
        assert!(CandidateBatch::parse_canonical("a\tmethod_mismatch\nb\tmethod_mismatch").is_err());
        assert!(
            CandidateBatch::parse_canonical("a\tmethod_mismatch\na\treplay_same_proof").is_err()
        );
    }

    #[test]
    fn deterministic_evaluator_owns_expected_protocol_results()
    -> Result<(), Box<dyn std::error::Error>> {
        let input = concat!(
            "method\tmethod_mismatch\n",
            "target\ttarget_mismatch\n",
            "query\tquery_variation_ignored\n",
            "token\taccess_token_mismatch\n",
            "nonce\tnonce_mismatch\n",
            "replay\treplay_same_proof",
        );
        let batch = CandidateBatch::parse_canonical(input)?;
        let results = batch.evaluate()?;

        assert_eq!(
            results[0].observed,
            ObservedOutcome::Rejected(DpopError::MethodMismatch)
        );
        assert_eq!(
            results[1].observed,
            ObservedOutcome::Rejected(DpopError::TargetMismatch)
        );
        assert_eq!(results[2].observed, ObservedOutcome::Verified);
        assert_eq!(
            results[3].observed,
            ObservedOutcome::Rejected(DpopError::AccessTokenHashMismatch)
        );
        assert_eq!(
            results[4].observed,
            ObservedOutcome::Rejected(DpopError::NonceMismatch)
        );
        assert_eq!(
            results[5].observed,
            ObservedOutcome::Rejected(DpopError::ReplayDetected)
        );
        assert_eq!(results[2].mutation, MutationKind::QueryVariationIgnored);
        assert!(results[2].novel_dimension);
        Ok(())
    }
}
