use crate::crypto::SerialNumber;
use crate::note::{NoteCommitmentData, SignedNote};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuanceRequest {
    pub blinded_candidates: Vec<NoteCommitmentData>,
    pub gateway_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuanceChallenge {
    pub session_id: String,
    pub open_indices: Vec<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsignedNoteReveal {
    pub index: usize,
    pub serial: SerialNumber,
    pub rho_bytes: Vec<u8>,
    pub pair_randomness: Vec<(Vec<u8>, Vec<u8>)>,
    pub a_bits: Vec<u8>,
    pub b_bits: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuanceReveal {
    pub session_id: String,
    pub revealed: Vec<UnsignedNoteReveal>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuanceResponse {
    pub signed_note: SignedNote,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendRequest {
    pub note: SignedNote,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendChallenge {
    pub challenge_bits: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WhichCommitment {
    A,
    B,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealedScalar {
    pub bit_index: usize,
    pub value_scalar: Vec<u8>,
    pub blinding_scalar: Vec<u8>,
    pub which: WhichCommitment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendProof {
    pub serial: SerialNumber,
    pub revealed_scalars: Vec<RevealedScalar>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendResponse {
    pub accepted: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub identity_id: String,
    pub theta_u: Vec<u8>,
    pub proof_of_identity: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub gateway_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityResolutionRequest {
    pub theta_u: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityResolutionResponse {
    pub identity_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintInRequest {
    pub note_hash: Vec<u8>,
    pub denomination_msat: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintInCommitment {
    pub mint_commitment: Vec<u8>,
    pub session_id: String,
    pub payment_request: String,
    pub payment_hash: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditResponse {
    pub issued_count: u64,
    pub spent_count: u64,
    pub outstanding: u64,
    pub issued_root: String,
    pub spent_root: String,
    pub anchored_at: Option<u64>,
    pub anchor_hash: Option<String>,
    pub anchor_slot: Option<u64>,
}
