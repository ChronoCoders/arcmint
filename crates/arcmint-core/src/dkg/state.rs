use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::dkg::transcript::TranscriptEntry;
use crate::dkg::types::{CeremonyConfig, DkgOutput, ParticipantId, Round1Package, Round2Package};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CeremonyPhase {
    WaitingForParticipants,
    Round1 { started_at: u64 },
    Round2 { started_at: u64 },
    Finalizing,
    Complete,
    Aborted { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CeremonyState {
    pub config: CeremonyConfig,
    pub phase: CeremonyPhase,
    pub joined: HashMap<ParticipantId, bool>,
    pub round1_packages: HashMap<ParticipantId, Round1Package>,
    pub round2_packages: HashMap<ParticipantId, Vec<Round2Package>>,
    pub outputs: HashMap<ParticipantId, DkgOutput>,
    pub transcript: Vec<TranscriptEntry>,
}

impl CeremonyState {
    pub fn all_joined(&self) -> bool {
        self.config
            .participants
            .iter()
            .all(|id| self.joined.get(id).copied().unwrap_or(false))
    }

    pub fn all_round1_complete(&self) -> bool {
        self.config
            .participants
            .iter()
            .all(|id| self.round1_packages.contains_key(id))
    }

    pub fn all_round2_complete(&self) -> bool {
        self.config
            .participants
            .iter()
            .all(|id| self.round2_complete_for(id))
    }

    pub fn round2_complete_for(&self, participant: &ParticipantId) -> bool {
        let expected = self
            .config
            .participants
            .iter()
            .filter(|id| *id != participant)
            .count();

        match self.round2_packages.get(participant) {
            Some(packages) => {
                let mut senders = HashSet::new();
                for package in packages {
                    if package.from != *participant {
                        senders.insert(package.from.clone());
                    }
                }
                senders.len() == expected
            }
            None => expected == 0,
        }
    }
}
