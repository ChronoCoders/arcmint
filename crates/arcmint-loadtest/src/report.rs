use crate::config::LoadTestConfig;
use crate::metrics::{LatencyStats, MetricsSnapshot};
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

#[derive(Serialize, Debug)]
pub enum SloResult {
    Pass,
    Fail {
        metric: String,
        threshold: String,
        actual: String,
    },
}

#[derive(Serialize, Debug)]
pub struct LoadTestReport {
    pub run_id: String,
    pub config: LoadTestConfig,
    pub started_at: String,
    pub completed_at: String,
    pub duration_secs: u64,
    pub metrics: MetricsSnapshot,
    pub slo_results: Vec<SloResult>,
    pub overall_pass: bool,
}

fn latency_slo(name: &str, stats: &LatencyStats, max_ms: u64) -> SloResult {
    if stats.p99_ms <= max_ms {
        SloResult::Pass
    } else {
        SloResult::Fail {
            metric: name.to_string(),
            threshold: format!("p99 <= {}ms", max_ms),
            actual: format!("p99 = {}ms", stats.p99_ms),
        }
    }
}

fn rate_slo(name: &str, failures: u64, successes: u64, max_rate: f64) -> SloResult {
    let total = failures + successes;
    if total == 0 {
        return SloResult::Pass;
    }
    let rate = failures as f64 / total as f64;
    if rate <= max_rate {
        SloResult::Pass
    } else {
        SloResult::Fail {
            metric: name.to_string(),
            threshold: format!("rate <= {:.4}", max_rate),
            actual: format!("rate = {:.4}", rate),
        }
    }
}

pub fn evaluate_slos(config: &LoadTestConfig, metrics: &MetricsSnapshot) -> Vec<SloResult> {
    let mut results = vec![
        latency_slo(
            "issuance_latency_p99_ms",
            &metrics.issuance_latency,
            config.issuance_p99_max_ms,
        ),
        latency_slo(
            "spend_latency_p99_ms",
            &metrics.spend_latency,
            config.spend_p99_max_ms,
        ),
        latency_slo(
            "signer_rpc_latency_p99_ms",
            &metrics.signer_rpc_latency,
            config.signer_rpc_p99_max_ms,
        ),
        latency_slo(
            "lightning_latency_p99_ms",
            &metrics.lightning_latency,
            config.lightning_settlement_p99_max_ms,
        ),
        rate_slo(
            "signing_failure_rate",
            metrics.issuance_failure,
            metrics.issuance_success,
            config.signing_failure_rate_max,
        ),
        rate_slo(
            "lightning_failure_rate",
            metrics.lightning_failure,
            metrics.lightning_success,
            config.lightning_failure_rate_max,
        ),
    ];
    if metrics.double_spend_false_negatives <= config.spend_false_negatives_allowed {
        results.push(SloResult::Pass);
    } else {
        results.push(SloResult::Fail {
            metric: "double_spend_false_negatives".to_string(),
            threshold: format!("<= {}", config.spend_false_negatives_allowed),
            actual: metrics.double_spend_false_negatives.to_string(),
        });
    }
    if metrics.registry_divergence_detected {
        results.push(SloResult::Fail {
            metric: "registry_divergence_detected".to_string(),
            threshold: "false".to_string(),
            actual: "true".to_string(),
        });
    } else {
        results.push(SloResult::Pass);
    }
    results
}

pub fn print_summary(report: &LoadTestReport) {
    let now = Utc::now().to_rfc3339();
    println!("ArcMint load test report {}", now);
    println!("Run ID: {}", report.run_id);
    println!("Duration: {}s", report.duration_secs);
    println!();
    println!(
        "{:<32} {:<20} {:<20} {:<8}",
        "Metric", "Threshold", "Actual", "Result"
    );
    for slo in &report.slo_results {
        match slo {
            SloResult::Pass => {
                let label = "PASS";
                let colored = format!("\x1b[32m{}\x1b[0m", label);
                println!("{:<32} {:<20} {:<20} {:<8}", "", "", "", colored);
            }
            SloResult::Fail {
                metric,
                threshold,
                actual,
            } => {
                let label = "FAIL";
                let colored = format!("\x1b[31m{}\x1b[0m", label);
                println!(
                    "{:<32} {:<20} {:<20} {:<8}",
                    metric, threshold, actual, colored
                );
            }
        }
    }
    if report.overall_pass {
        println!("\x1b[32mOVERALL PASS\x1b[0m");
    } else {
        println!("\x1b[31mOVERALL FAIL\x1b[0m");
    }
}

pub fn save_report(report: &LoadTestReport, path: &Path) -> Result<()> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, report)?;
    Ok(())
}
