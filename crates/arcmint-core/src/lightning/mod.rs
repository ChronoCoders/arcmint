use crate::crypto::SerialNumber;
use sha2::{Digest, Sha256};
use std::time::Instant;

pub mod backend;
pub mod error;
pub mod settlement;
pub mod types;

#[derive(Clone, Debug)]
pub struct MintCommitmentPreimage {
    pub note_hash: [u8; 32],
    pub session_id: String,
    pub pubkey_bytes: Vec<u8>,
}

pub fn compute_mint_commitment(preimage: &MintCommitmentPreimage) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(preimage.note_hash);
    hasher.update(preimage.session_id.as_bytes());
    hasher.update(&preimage.pubkey_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn verify_mint_commitment(commitment: &[u8; 32], preimage: &MintCommitmentPreimage) -> bool {
    compute_mint_commitment(preimage) == *commitment
}

#[derive(Clone, Debug)]
pub enum MintInState {
    AwaitingPayment,
    HtlcOpen,
    Signed,
    Expired,
}

#[derive(Clone, Debug)]
pub struct MintInSession {
    pub note_hash: [u8; 32],
    pub session_id: String,
    pub mint_commitment: [u8; 32],
    pub payment_hash: [u8; 32],
    pub payment_request: String,
    pub denomination_msat: u64,
    pub state: MintInState,
    pub created_at: Instant,
    pub signature: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub enum MintOutState {
    PendingSettlement,
    Succeeded,
    Failed,
}

#[derive(Clone, Debug)]
pub struct MintOutSession {
    pub serial: SerialNumber,
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
    pub state: MintOutState,
}
