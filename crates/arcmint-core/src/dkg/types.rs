use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::dkg::error::DkgError;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParticipantId(pub String);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CeremonyConfig {
    pub ceremony_id: String,
    pub threshold: u16,
    pub max_signers: u16,
    pub participants: Vec<ParticipantId>,
    pub round_timeout_secs: u64,
}

impl CeremonyConfig {
    pub fn validate(&self) -> Result<(), DkgError> {
        if self.threshold <= 1 {
            return Err(DkgError::InvalidParticipantCount {
                n: self.max_signers,
                t: self.threshold,
            });
        }

        if self.max_signers < 3 {
            return Err(DkgError::InvalidParticipantCount {
                n: self.max_signers,
                t: self.threshold,
            });
        }

        if self.threshold > self.max_signers {
            return Err(DkgError::InvalidParticipantCount {
                n: self.max_signers,
                t: self.threshold,
            });
        }

        if self.participants.len() != self.max_signers as usize {
            return Err(DkgError::InvalidParticipantCount {
                n: self.max_signers,
                t: self.threshold,
            });
        }

        let mut seen = HashSet::new();
        for participant in &self.participants {
            if !seen.insert(participant.0.clone()) {
                return Err(DkgError::DuplicateParticipant(participant.0.clone()));
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Package {
    pub participant_id: ParticipantId,
    pub commitment: Vec<Vec<u8>>,
    pub proof_of_knowledge: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Package {
    pub from: ParticipantId,
    pub to: ParticipantId,
    pub encrypted_share: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgOutput {
    pub participant_id: ParticipantId,
    pub key_package: Vec<u8>,
    pub public_key_package: Vec<u8>,
}
