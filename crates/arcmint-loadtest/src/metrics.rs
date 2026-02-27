use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

pub struct LatencyRecorder {
    hist: Histogram<u64>,
}

impl LatencyRecorder {
    pub fn new() -> Self {
        let hist = Histogram::new_with_bounds(1, 60_000, 3).expect("valid histogram bounds");
        Self { hist }
    }

    pub fn record(&mut self, ms: u64) {
        let _ = self.hist.record(ms);
    }

    pub fn p50(&self) -> u64 {
        self.hist.value_at_quantile(0.5)
    }

    pub fn p95(&self) -> u64 {
        self.hist.value_at_quantile(0.95)
    }

    pub fn p99(&self) -> u64 {
        self.hist.value_at_quantile(0.99)
    }

    pub fn max(&self) -> u64 {
        self.hist.max()
    }

    pub fn count(&self) -> u64 {
        self.hist.len()
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct LatencyStats {
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
    pub max_ms: u64,
    pub count: u64,
}

pub struct LoadTestMetricsInner {
    pub issuance_latency: LatencyRecorder,
    pub spend_latency: LatencyRecorder,
    pub signer_rpc_latency: LatencyRecorder,
    pub lightning_latency: LatencyRecorder,
    pub issuance_success: u64,
    pub issuance_failure: u64,
    pub spend_success: u64,
    pub spend_failure: u64,
    pub double_spend_attempts: u64,
    pub double_spend_false_negatives: u64,
    pub lightning_success: u64,
    pub lightning_failure: u64,
    pub panics: u64,
    pub registry_divergence_detected: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub issuance_latency: LatencyStats,
    pub spend_latency: LatencyStats,
    pub signer_rpc_latency: LatencyStats,
    pub lightning_latency: LatencyStats,
    pub issuance_success: u64,
    pub issuance_failure: u64,
    pub spend_success: u64,
    pub spend_failure: u64,
    pub double_spend_attempts: u64,
    pub double_spend_false_negatives: u64,
    pub lightning_success: u64,
    pub lightning_failure: u64,
    pub panics: u64,
    pub registry_divergence_detected: bool,
}

#[derive(Clone)]
pub struct LoadTestMetrics {
    inner: Arc<Mutex<LoadTestMetricsInner>>,
}

impl LoadTestMetrics {
    pub fn new() -> Self {
        let inner = LoadTestMetricsInner {
            issuance_latency: LatencyRecorder::new(),
            spend_latency: LatencyRecorder::new(),
            signer_rpc_latency: LatencyRecorder::new(),
            lightning_latency: LatencyRecorder::new(),
            issuance_success: 0,
            issuance_failure: 0,
            spend_success: 0,
            spend_failure: 0,
            double_spend_attempts: 0,
            double_spend_false_negatives: 0,
            lightning_success: 0,
            lightning_failure: 0,
            panics: 0,
            registry_divergence_detected: false,
        };
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    pub fn with_mut<F>(&self, f: F)
    where
        F: FnOnce(&mut LoadTestMetricsInner),
    {
        if let Ok(mut guard) = self.inner.lock() {
            f(&mut guard);
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let guard = self.inner.lock().expect("metrics lock");
        let issuance_latency = &guard.issuance_latency;
        let spend_latency = &guard.spend_latency;
        let signer_rpc_latency = &guard.signer_rpc_latency;
        let lightning_latency = &guard.lightning_latency;
        MetricsSnapshot {
            issuance_latency: LatencyStats {
                p50_ms: issuance_latency.p50(),
                p95_ms: issuance_latency.p95(),
                p99_ms: issuance_latency.p99(),
                max_ms: issuance_latency.max(),
                count: issuance_latency.count(),
            },
            spend_latency: LatencyStats {
                p50_ms: spend_latency.p50(),
                p95_ms: spend_latency.p95(),
                p99_ms: spend_latency.p99(),
                max_ms: spend_latency.max(),
                count: spend_latency.count(),
            },
            signer_rpc_latency: LatencyStats {
                p50_ms: signer_rpc_latency.p50(),
                p95_ms: signer_rpc_latency.p95(),
                p99_ms: signer_rpc_latency.p99(),
                max_ms: signer_rpc_latency.max(),
                count: signer_rpc_latency.count(),
            },
            lightning_latency: LatencyStats {
                p50_ms: lightning_latency.p50(),
                p95_ms: lightning_latency.p95(),
                p99_ms: lightning_latency.p99(),
                max_ms: lightning_latency.max(),
                count: lightning_latency.count(),
            },
            issuance_success: guard.issuance_success,
            issuance_failure: guard.issuance_failure,
            spend_success: guard.spend_success,
            spend_failure: guard.spend_failure,
            double_spend_attempts: guard.double_spend_attempts,
            double_spend_false_negatives: guard.double_spend_false_negatives,
            lightning_success: guard.lightning_success,
            lightning_failure: guard.lightning_failure,
            panics: guard.panics,
            registry_divergence_detected: guard.registry_divergence_detected,
        }
    }
}
