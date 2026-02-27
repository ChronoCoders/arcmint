use thiserror::Error;

#[derive(Debug, Error)]
pub enum DkgError {
    #[error("invalid participant count: n={n}, t={t}")]
    InvalidParticipantCount { n: u16, t: u16 },

    #[error("duplicate participant: {0}")]
    DuplicateParticipant(String),

    #[error("invalid commitment from {participant}: {reason}")]
    InvalidCommitment { participant: String, reason: String },

    #[error("invalid proof of knowledge from {participant}")]
    InvalidProofOfKnowledge { participant: String },

    #[error("invalid share from {from} to {to}")]
    InvalidShare { from: String, to: String },

    #[error("missing participant: {0}")]
    MissingParticipant(String),

    #[error("ceremony aborted: {reason}")]
    CeremonyAborted { reason: String },

    #[error("round {round} timeout waiting for {participant}")]
    RoundTimeout { round: u8, participant: String },

    #[error("transcript error: {0}")]
    TranscriptError(String),

    #[error("auth error: {0}")]
    AuthError(String),
}
