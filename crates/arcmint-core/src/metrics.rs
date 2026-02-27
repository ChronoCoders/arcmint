use lazy_static::lazy_static;
use prometheus::{
    register_counter, register_counter_vec, register_gauge, register_gauge_vec, register_histogram,
    register_histogram_vec, Counter, CounterVec, Encoder, Gauge, GaugeVec, Histogram, HistogramVec,
    TextEncoder,
};

lazy_static! {
    pub static ref FROST_ROUND_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "frost_round_duration_seconds",
        "Duration of FROST signing rounds",
        &["round", "signer_id"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
    )
    .unwrap();
    pub static ref SIGNING_FAILURES_TOTAL: CounterVec = register_counter_vec!(
        "signing_failures_total",
        "Total number of FROST signing failures",
        &["signer_id", "reason"]
    )
    .unwrap();
    pub static ref DOUBLE_SPEND_ATTEMPTS_TOTAL: Counter = register_counter!(
        "double_spend_attempts_total",
        "Total number of double spend attempts detected"
    )
    .unwrap();
    pub static ref DB_WRITE_LATENCY_SECONDS: HistogramVec = register_histogram_vec!(
        "db_write_latency_seconds",
        "Latency of database write operations",
        &["operation"],
        vec![0.0001, 0.001, 0.005, 0.01, 0.05, 0.1]
    )
    .unwrap();
    pub static ref ACTIVE_NONCES_COUNT: GaugeVec = register_gauge_vec!(
        "active_nonces_count",
        "Number of active FROST signing nonces",
        &["signer_id"]
    )
    .unwrap();
    pub static ref ISSUANCE_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "issuance_requests_total",
        "Total issuance requests by outcome",
        &["status"]
    )
    .unwrap();
    pub static ref SPEND_VERIFICATION_LATENCY_SECONDS: Histogram = register_histogram!(
        "spend_verification_latency_seconds",
        "Latency of spend verification operations",
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
    )
    .unwrap();
    pub static ref SIGNER_RPC_LATENCY_SECONDS: HistogramVec = register_histogram_vec!(
        "signer_rpc_latency_seconds",
        "Latency of RPC calls to signers",
        &["signer_id", "operation"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
    )
    .unwrap();
    pub static ref ANCHOR_SUBMIT_TOTAL: CounterVec = register_counter_vec!(
        "anchor_submit_total",
        "Total anchoring submissions by status",
        &["status"]
    )
    .unwrap();
    pub static ref ANCHOR_SLOT: Gauge =
        register_gauge!("anchor_slot", "Latest anchored slot or height").unwrap();
    pub static ref ACTIVE_SESSIONS_COUNT: Gauge = register_gauge!(
        "active_sessions_count",
        "Number of active coordinator sessions"
    )
    .unwrap();
    pub static ref MINT_IN_TOTAL: CounterVec = register_counter_vec!(
        "mint_in_total",
        "Total mint-in operations by status",
        &["status"]
    )
    .unwrap();
    pub static ref MINT_OUT_TOTAL: CounterVec = register_counter_vec!(
        "mint_out_total",
        "Total mint-out operations by status",
        &["status"]
    )
    .unwrap();
    pub static ref LIGHTNING_PAYMENT_LATENCY_SECONDS: Histogram = register_histogram!(
        "lightning_payment_latency_seconds",
        "Latency of Lightning payments and invoice settlements"
    )
    .unwrap();
    pub static ref INVOICE_SETTLEMENT_FAILURES_TOTAL: Counter = register_counter!(
        "invoice_settlement_failures_total",
        "Total number of Lightning invoice settlement failures"
    )
    .unwrap();
    pub static ref CHANNEL_BALANCE_LOCAL_MSAT: Gauge = register_gauge!(
        "channel_balance_local_msat",
        "Total local channel balance in millisatoshis"
    )
    .unwrap();
    pub static ref ANCHOR_CONFIRMATIONS: GaugeVec = register_gauge_vec!(
        "anchor_confirmations",
        "Current confirmation depth of anchor transactions",
        &["txid"]
    )
    .unwrap();
    pub static ref ANCHOR_REORGS_TOTAL: Counter = register_counter!(
        "anchor_reorgs_total",
        "Total number of anchor re-orgs detected"
    )
    .unwrap();
    pub static ref ANCHOR_EVICTIONS_TOTAL: Counter = register_counter!(
        "anchor_evictions_total",
        "Total number of anchor evictions detected"
    )
    .unwrap();
    pub static ref ANCHOR_FEE_BUMPS_TOTAL: Counter = register_counter!(
        "anchor_fee_bumps_total",
        "Total number of anchor fee bumps attempted"
    )
    .unwrap();
    pub static ref CHANNEL_BALANCE_REMOTE_MSAT: Gauge = register_gauge!(
        "channel_balance_remote_msat",
        "Total remote channel balance in millisatoshis"
    )
    .unwrap();
    pub static ref REGISTRATION_ATTEMPTS_TOTAL: CounterVec = register_counter_vec!(
        "registration_attempts_total",
        "Total gateway registration attempts by outcome",
        &["status"]
    )
    .unwrap();
    pub static ref RATE_LIMIT_HITS_TOTAL: Counter = register_counter!(
        "rate_limit_hits_total",
        "Total number of rate limit hits at gateway"
    )
    .unwrap();
    pub static ref RESOLVE_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "resolve_requests_total",
        "Total resolve requests by outcome",
        &["status"]
    )
    .unwrap();
    pub static ref MERCHANT_KEY_VALIDATION_TOTAL: CounterVec = register_counter_vec!(
        "merchant_key_validation_total",
        "Total merchant key validations by outcome",
        &["status"]
    )
    .unwrap();
    pub static ref GATEWAY_TOKEN_ISSUED_TOTAL: Counter = register_counter!(
        "gateway_token_issued_total",
        "Total number of gateway tokens issued"
    )
    .unwrap();
    pub static ref NOTE_VERIFICATION_FAILURES_TOTAL: CounterVec = register_counter_vec!(
        "note_verification_failures_total",
        "Total note verification failures at merchant",
        &["reason"]
    )
    .unwrap();
    pub static ref ACCEPTED_PAYMENTS_TOTAL: Counter = register_counter!(
        "accepted_payments_total",
        "Total number of accepted payments at merchant"
    )
    .unwrap();
    pub static ref PAYMENT_INITIATION_TOTAL: CounterVec = register_counter_vec!(
        "payment_initiation_total",
        "Total payment initiation attempts by status",
        &["status"]
    )
    .unwrap();
    pub static ref PENDING_SPEND_COUNT: Gauge = register_gauge!(
        "pending_spend_count",
        "Current number of pending spends at merchant"
    )
    .unwrap();
    pub static ref EXPIRED_PENDING_SPENDS_TOTAL: Counter = register_counter!(
        "expired_pending_spends_total",
        "Total number of expired pending spends cleaned up"
    )
    .unwrap();
}

pub fn render_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    if encoder.encode(&metric_families, &mut buffer).is_ok() {
        String::from_utf8(buffer).unwrap_or_default()
    } else {
        String::new()
    }
}
