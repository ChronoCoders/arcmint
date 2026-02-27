use anyhow::Result;

use crate::attacks::{crypto, protocol};
use crate::client::AdversaryClient;
use crate::report::{AdversaryReport, AttackResult};
use crate::CliConfig;

pub struct AttackRunner {
    pub client: AdversaryClient,
    pub config: CliConfig,
    pub report: AdversaryReport,
}

impl AttackRunner {
    pub async fn run_all(&mut self, include_slow: bool) -> Result<bool> {
        self.config.include_slow = include_slow;
        let mut all_passed = true;

        let r1 = crypto::attack_forged_signature(&self.client, &self.config).await;
        all_passed &= self.record(r1);

        let r2 = protocol::attack_malformed_note_missing_pairs(&self.client, &self.config).await;
        all_passed &= self.record(r2);

        let r3 =
            protocol::attack_malformed_note_wrong_denomination(&self.client, &self.config).await;
        all_passed &= self.record(r3);

        let r4 =
            protocol::attack_registry_bypass_skip_issued_check(&self.client, &self.config).await;
        all_passed &= self.record(r4);

        let r5 = crypto::attack_wrong_commitment_opening(&self.client, &self.config).await;
        all_passed &= self.record(r5);

        let r6 = crypto::attack_challenge_precomputation(&self.client, &self.config).await;
        all_passed &= self.record(r6);

        let r7 = crypto::attack_double_spend(&self.client, &self.config).await;
        all_passed &= self.record(r7);

        let r8 = crypto::attack_double_spend_different_merchants(&self.client, &self.config).await;
        all_passed &= self.record(r8);

        let r9 = crypto::attack_theta_recovery_verification(&self.client, &self.config).await;
        all_passed &= self.record(r9);

        let r10 = protocol::attack_replay_spent_note(&self.client, &self.config).await;
        all_passed &= self.record(r10);

        let r11 = protocol::attack_flood_issuance(&self.client, &self.config).await;
        all_passed &= self.record(r11);

        let r12 = protocol::attack_signer_direct_access(&self.client, &self.config).await;
        all_passed &= self.record(r12);

        let r13 = protocol::attack_malformed_issuance_reveal(&self.client, &self.config).await;
        all_passed &= self.record(r13);

        let r14 = protocol::attack_expired_note(&self.client, &self.config).await;
        all_passed &= self.record(r14);

        self.report.finalize();
        self.report.print_summary();

        if let Some(path) = &self.config.output {
            self.report.save(path)?;
        }

        Ok(all_passed)
    }

    pub async fn run_single(&mut self, attack_name: &str, include_slow: bool) -> Result<bool> {
        self.config.include_slow = include_slow;

        let result = match attack_name {
            "double-spend" => crypto::attack_double_spend(&self.client, &self.config).await,
            "forged-signature" => crypto::attack_forged_signature(&self.client, &self.config).await,
            "malformed-note-missing-pairs" => {
                protocol::attack_malformed_note_missing_pairs(&self.client, &self.config).await
            }
            "malformed-note-wrong-denomination" => {
                protocol::attack_malformed_note_wrong_denomination(&self.client, &self.config).await
            }
            "registry-bypass" => {
                protocol::attack_registry_bypass_skip_issued_check(&self.client, &self.config).await
            }
            "wrong-commitment-opening" => {
                crypto::attack_wrong_commitment_opening(&self.client, &self.config).await
            }
            "challenge-precomputation" => {
                crypto::attack_challenge_precomputation(&self.client, &self.config).await
            }
            "double-spend-different-merchants" => {
                crypto::attack_double_spend_different_merchants(&self.client, &self.config).await
            }
            "theta-recovery-verification" => {
                crypto::attack_theta_recovery_verification(&self.client, &self.config).await
            }
            "replay-spent-note" => {
                protocol::attack_replay_spent_note(&self.client, &self.config).await
            }
            "flood-issuance" => protocol::attack_flood_issuance(&self.client, &self.config).await,
            "signer-direct-access" => {
                protocol::attack_signer_direct_access(&self.client, &self.config).await
            }
            "malformed-issuance-reveal" => {
                protocol::attack_malformed_issuance_reveal(&self.client, &self.config).await
            }
            "expired-note" => protocol::attack_expired_note(&self.client, &self.config).await,
            _ => {
                return Ok(true);
            }
        };

        self.print_result(&result);
        self.report.add_result(result);
        self.report.finalize();
        self.report.print_summary();

        if let Some(path) = &self.config.output {
            self.report.save(path)?;
        }

        Ok(self.report.failed == 0)
    }

    fn record(&mut self, result: AttackResult) -> bool {
        let success = result.success;
        self.print_result(&result);
        self.report.add_result(result);
        success
    }

    fn print_result(&self, result: &AttackResult) {
        let status = if result.success { "PASS" } else { "FAIL" };
        let color = if result.success {
            "\x1b[32m"
        } else {
            "\x1b[31m"
        };
        let reset = "\x1b[0m";
        println!(
            "{}{}{} {} ({} ms)",
            color, status, reset, result.attack_name, result.duration_ms
        );
    }
}
