use std::path::Path;

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::CliConfig;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AttackResult {
    pub attack_name: String,
    pub target: String,
    pub success: bool,
    pub expected_behavior: String,
    pub observed_behavior: String,
    pub status_code: Option<u16>,
    pub response_body: Option<String>,
    pub duration_ms: u64,
    pub timestamp: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AdversaryReport {
    pub run_id: String,
    pub started_at: String,
    pub completed_at: String,
    pub coordinator_url: String,
    pub total_attacks: usize,
    pub passed: usize,
    pub failed: usize,
    pub results: Vec<AttackResult>,
}

impl AdversaryReport {
    pub fn new(config: &CliConfig) -> Self {
        let now = Utc::now().to_rfc3339();
        AdversaryReport {
            run_id: Uuid::new_v4().to_string(),
            started_at: now.clone(),
            completed_at: now,
            coordinator_url: config.coordinator_url.clone(),
            total_attacks: 0,
            passed: 0,
            failed: 0,
            results: Vec::new(),
        }
    }

    pub fn add_result(&mut self, result: AttackResult) {
        self.total_attacks += 1;
        if result.success {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
        self.results.push(result);
    }

    pub fn finalize(&mut self) {
        self.completed_at = Utc::now().to_rfc3339();
    }

    pub fn print_summary(&self) {
        println!(
            "{:<24} {:<16} {:<8} {:>10}",
            "Attack", "Target", "Result", "Duration"
        );
        println!("{:-<24} {:-<16} {:-<8} {:-<10}", "", "", "", "");
        for result in &self.results {
            let status = if result.success { "PASS" } else { "FAIL" };
            println!(
                "{:<24} {:<16} {:<8} {:>10}ms",
                result.attack_name, result.target, status, result.duration_ms
            );
        }
        println!(
            "\nTotal: {}, Passed: {}, Failed: {}",
            self.total_attacks, self.passed, self.failed
        );
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)?;
        Ok(())
    }
}
