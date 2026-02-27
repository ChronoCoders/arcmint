use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dkg::types::{CeremonyConfig, ParticipantId};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TranscriptEntry {
    pub timestamp: u64,
    pub event: TranscriptEvent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TranscriptEvent {
    CeremonyStarted {
        config: CeremonyConfig,
    },
    ParticipantJoined {
        id: ParticipantId,
    },
    Round1Submitted {
        participant: ParticipantId,
        commitment_hash: String,
    },
    Round2Submitted {
        from: ParticipantId,
        to: ParticipantId,
    },
    OutputIssued {
        participant: ParticipantId,
        public_key_hash: String,
    },
    CeremonyCompleted {
        public_key_hash: String,
    },
    CeremonyAborted {
        reason: String,
    },
}

pub fn compute_transcript_hash(entries: &[TranscriptEntry]) -> [u8; 32] {
    let json = serde_json::to_vec(entries).expect("failed to serialize transcript entries");
    let mut hasher = Sha256::new();
    hasher.update(&json);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
