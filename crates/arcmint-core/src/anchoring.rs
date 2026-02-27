use crate::error::{ArcMintError, Result};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

pub mod bitcoin_rpc;
pub mod tracker;
pub mod tx_builder;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnchorPayload {
    pub commitment_hash: [u8; 32],
    pub slot: u64,
    pub version: u8,
}

pub fn encode_anchor_payload(payload: &AnchorPayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(41);
    out.push(payload.version);
    out.extend_from_slice(&payload.slot.to_be_bytes());
    out.extend_from_slice(&payload.commitment_hash);
    out
}

pub fn decode_anchor_payload(data: &[u8]) -> Result<AnchorPayload> {
    if data.len() != 41 {
        return Err(ArcMintError::CryptoError(
            "invalid anchor payload length".to_string(),
        ));
    }

    let version = data[0];

    let mut slot_bytes = [0u8; 8];
    slot_bytes.copy_from_slice(&data[1..9]);
    let slot = u64::from_be_bytes(slot_bytes);

    let mut commitment_hash = [0u8; 32];
    commitment_hash.copy_from_slice(&data[9..41]);

    Ok(AnchorPayload {
        commitment_hash,
        slot,
        version,
    })
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnchorRecord {
    pub payload: AnchorPayload,
    pub txid: Option<String>,
    pub anchored_at: SystemTime,
}
