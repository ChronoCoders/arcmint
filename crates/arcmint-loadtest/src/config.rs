use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LoadTestConfig {
    pub concurrency: usize,
    pub duration_secs: u64,
    pub ramp_up_secs: u64,
    pub full_pipeline_weight: u8,
    pub issuance_burst_weight: u8,
    pub double_spend_weight: u8,
    pub denomination_msat: u64,
    pub k: usize,
    pub issuance_p99_max_ms: u64,
    pub spend_p99_max_ms: u64,
    pub signer_rpc_p99_max_ms: u64,
    pub lightning_settlement_p99_max_ms: u64,
    pub signing_failure_rate_max: f64,
    pub lightning_failure_rate_max: f64,
    pub spend_false_negatives_allowed: u64,
    pub coordinator_url: String,
    pub gateway_url: String,
    pub merchant_url: String,
    pub signer_urls: Vec<String>,
    pub ca_cert_path: Option<String>,
}

impl Default for LoadTestConfig {
    fn default() -> Self {
        Self {
            concurrency: 10,
            duration_secs: 60,
            ramp_up_secs: 5,
            full_pipeline_weight: 70,
            issuance_burst_weight: 20,
            double_spend_weight: 10,
            denomination_msat: 100_000,
            k: 32,
            issuance_p99_max_ms: 2_000,
            spend_p99_max_ms: 1_000,
            signer_rpc_p99_max_ms: 500,
            lightning_settlement_p99_max_ms: 5_000,
            signing_failure_rate_max: 0.001,
            lightning_failure_rate_max: 0.01,
            spend_false_negatives_allowed: 0,
            coordinator_url: String::new(),
            gateway_url: String::new(),
            merchant_url: String::new(),
            signer_urls: Vec::new(),
            ca_cert_path: None,
        }
    }
}

impl LoadTestConfig {
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let cfg: LoadTestConfig = toml::from_str(&data)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.concurrency == 0 {
            return Err(anyhow!("concurrency must be > 0"));
        }
        if self.duration_secs == 0 {
            return Err(anyhow!("duration_secs must be > 0"));
        }
        let total_weight = self.full_pipeline_weight as u16
            + self.issuance_burst_weight as u16
            + self.double_spend_weight as u16;
        if total_weight != 100 {
            return Err(anyhow!(
                "scenario weights must sum to 100, got {}",
                total_weight
            ));
        }
        Ok(())
    }
}
