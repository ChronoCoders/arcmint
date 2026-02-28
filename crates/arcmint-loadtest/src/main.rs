mod config;
mod lnd_client;
mod metrics;
mod report;

use crate::config::LoadTestConfig;
use crate::lnd_client::LndTestClient;
use crate::metrics::LoadTestMetrics;
use crate::report::{evaluate_slos, save_report, LoadTestReport};
use anyhow::{anyhow, Context, Result};
use arcmint_core::crypto::{
    compute_theta, hash_identity, random_scalar, BlindingFactor, Scalar, SerialNumber,
};
use arcmint_core::note::{generate_note_candidate, SignedNote, UnsignedNote};
use arcmint_core::protocol::{
    IssuanceChallenge, IssuanceRequest, IssuanceResponse, IssuanceReveal, RegistrationRequest,
    RegistrationResponse, SpendChallenge, SpendProof, SpendRequest, SpendResponse,
    UnsignedNoteReveal,
};
use arcmint_core::spending::generate_spend_proof;
use clap::{Parser, Subcommand};
use curve25519_dalek::scalar::Scalar as DalekScalar;
use rand::rngs::OsRng;
use rand::Rng;
use reqwest::Client;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Subcommand, Debug, Clone)]
enum Command {
    RunFull,
    RunIssuance,
    RunSpendRace,
    RunAll,
    CheckConfig,
}

#[derive(Parser, Debug)]
#[command(name = "arcmint-loadtest")]
#[command(about = "ArcMint federation load test tool")]
struct Cli {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    concurrency: Option<usize>,
    #[arg(long)]
    duration_secs: Option<u64>,
    #[arg(long)]
    ramp_up_secs: Option<u64>,
    #[arg(long)]
    full_pipeline_weight: Option<u8>,
    #[arg(long)]
    issuance_burst_weight: Option<u8>,
    #[arg(long)]
    double_spend_weight: Option<u8>,
    #[arg(long)]
    denomination_msat: Option<u64>,
    #[arg(long)]
    k: Option<usize>,
    #[arg(long)]
    issuance_p99_max_ms: Option<u64>,
    #[arg(long)]
    spend_p99_max_ms: Option<u64>,
    #[arg(long)]
    signer_rpc_p99_max_ms: Option<u64>,
    #[arg(long)]
    lightning_settlement_p99_max_ms: Option<u64>,
    #[arg(long)]
    signing_failure_rate_max: Option<f64>,
    #[arg(long)]
    lightning_failure_rate_max: Option<f64>,
    #[arg(long)]
    spend_false_negatives_allowed: Option<u64>,
    #[arg(long)]
    coordinator_url: Option<String>,
    #[arg(long)]
    gateway_url: Option<String>,
    #[arg(long)]
    merchant_url: Option<String>,
    #[arg(long)]
    signer_urls: Vec<String>,
    #[arg(long)]
    ca_cert_path: Option<String>,
    #[command(subcommand)]
    command: Command,
}

struct LoadTestContext {
    client: Client,
    coordinator_url: String,
    gateway_url: String,
    merchant_url: String,
    k: usize,
    denomination: u64,
}

fn env_or<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

fn env_string(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn apply_overrides(mut cfg: LoadTestConfig, cli: &Cli) -> LoadTestConfig {
    if let Some(v) = cli.concurrency.or_else(|| env_or("CONCURRENCY")) {
        cfg.concurrency = v;
    }
    if let Some(v) = cli.duration_secs.or_else(|| env_or("DURATION_SECS")) {
        cfg.duration_secs = v;
    }
    if let Some(v) = cli.ramp_up_secs.or_else(|| env_or("RAMP_UP_SECS")) {
        cfg.ramp_up_secs = v;
    }
    if let Some(v) = cli.full_pipeline_weight {
        cfg.full_pipeline_weight = v;
    }
    if let Some(v) = cli.issuance_burst_weight {
        cfg.issuance_burst_weight = v;
    }
    if let Some(v) = cli.double_spend_weight {
        cfg.double_spend_weight = v;
    }
    if let Some(v) = cli.denomination_msat {
        cfg.denomination_msat = v;
    }
    if let Some(v) = cli.k {
        cfg.k = v;
    }
    if let Some(v) = cli.issuance_p99_max_ms {
        cfg.issuance_p99_max_ms = v;
    }
    if let Some(v) = cli.spend_p99_max_ms {
        cfg.spend_p99_max_ms = v;
    }
    if let Some(v) = cli.signer_rpc_p99_max_ms {
        cfg.signer_rpc_p99_max_ms = v;
    }
    if let Some(v) = cli.lightning_settlement_p99_max_ms {
        cfg.lightning_settlement_p99_max_ms = v;
    }
    if let Some(v) = cli.signing_failure_rate_max {
        cfg.signing_failure_rate_max = v;
    }
    if let Some(v) = cli.lightning_failure_rate_max {
        cfg.lightning_failure_rate_max = v;
    }
    if let Some(v) = cli.spend_false_negatives_allowed {
        cfg.spend_false_negatives_allowed = v;
    }
    if let Some(v) = cli.coordinator_url.clone().or_else(|| env_string("COORDINATOR_URL")) {
        cfg.coordinator_url = v;
    }
    if let Some(v) = cli.gateway_url.clone().or_else(|| env_string("GATEWAY_URL")) {
        cfg.gateway_url = v;
    }
    if let Some(v) = cli.merchant_url.clone().or_else(|| env_string("MERCHANT_URL")) {
        cfg.merchant_url = v;
    }
    if !cli.signer_urls.is_empty() {
        cfg.signer_urls = cli.signer_urls.clone();
    } else if let Some(v) = env_string("SIGNER_URLS") {
        cfg.signer_urls = v.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Some(v) = cli.ca_cert_path.clone().or_else(|| env_string("CA_CERT_PATH")) {
        cfg.ca_cert_path = Some(v);
    }
    cfg
}

fn build_http_client(cfg: &LoadTestConfig) -> Result<Client> {
    let mut builder = Client::builder().timeout(Duration::from_secs(30));

    if let Some(ref ca_path) = cfg.ca_cert_path {
        let ca_bytes = std::fs::read(ca_path)
            .with_context(|| format!("failed to read CA cert from {ca_path}"))?;
        let cert = reqwest::Certificate::from_pem(&ca_bytes)
            .with_context(|| "failed to parse CA certificate")?;
        builder = builder.add_root_certificate(cert);
    }

    builder.build().with_context(|| "failed to build HTTP client")
}

async fn register_identity(ctx: &LoadTestContext) -> Result<(String, [u8; 32], String)> {
    let identity_id = format!("loadtest-{}", Uuid::new_v4());
    let mut rng = OsRng;
    let r_u = random_scalar(&mut rng);
    let h_u = hash_identity(&identity_id);
    let theta_u = compute_theta(&h_u, &r_u);

    let req = RegistrationRequest {
        identity_id: identity_id.clone(),
        theta_u: theta_u.to_vec(),
        proof_of_identity: String::new(),
    };

    let url = format!("{}/register", ctx.gateway_url);
    let resp = ctx.client.post(&url).json(&req).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "registration failed with HTTP {}",
            resp.status()
        ));
    }
    let reg_resp: RegistrationResponse = resp.json().await?;

    Ok((identity_id, theta_u, reg_resp.gateway_token))
}

async fn issue_note(
    ctx: &LoadTestContext,
    theta_u: &[u8; 32],
    gateway_token: &str,
) -> Result<(SignedNote, UnsignedNote)> {
    let k = ctx.k;
    let denomination = ctx.denomination;
    let mut rng = OsRng;

    let mut unsigned_candidates = Vec::with_capacity(k);
    let mut blinded_candidates = Vec::with_capacity(k);

    for _ in 0..k {
        let unsigned = generate_note_candidate(theta_u, denomination, k, &mut rng)?;
        blinded_candidates.push(unsigned.data.clone());
        unsigned_candidates.push(unsigned);
    }

    let issue_req = IssuanceRequest {
        blinded_candidates,
        gateway_token: gateway_token.to_string(),
    };

    let begin_url = format!("{}/issue/begin", ctx.coordinator_url);
    let begin_resp = ctx.client.post(&begin_url).json(&issue_req).send().await?;
    if !begin_resp.status().is_success() {
        return Err(anyhow!(
            "issue/begin failed with HTTP {}",
            begin_resp.status()
        ));
    }
    let challenge: IssuanceChallenge = begin_resp.json().await?;

    let open_indices = challenge.open_indices.clone();
    let mut closed_index = None;
    for idx in 0..k {
        if !open_indices.contains(&idx) {
            closed_index = Some(idx);
            break;
        }
    }
    let closed_index = closed_index.ok_or_else(|| anyhow!("no closed index in challenge"))?;

    let mut revealed = Vec::with_capacity(open_indices.len());
    for idx in &open_indices {
        let unsigned = &unsigned_candidates[*idx];
        let rho_bytes = vec![0u8; 32];
        let mut pair_randomness = Vec::with_capacity(unsigned.pair_randomness.len());
        for (ra, rb) in &unsigned.pair_randomness {
            let ra_bytes = ra.0.to_bytes().to_vec();
            let rb_bytes = rb.0.to_bytes().to_vec();
            pair_randomness.push((ra_bytes, rb_bytes));
        }
        let reveal = UnsignedNoteReveal {
            index: *idx,
            serial: unsigned.data.serial,
            rho_bytes,
            a_bits: unsigned.a_bits.clone(),
            b_bits: unsigned.b_bits.clone(),
            pair_randomness,
        };
        revealed.push(reveal);
    }

    let reveal_req = IssuanceReveal {
        session_id: challenge.session_id,
        revealed,
    };

    let reveal_url = format!("{}/issue/reveal", ctx.coordinator_url);
    let reveal_resp = ctx.client.post(&reveal_url).json(&reveal_req).send().await?;
    if !reveal_resp.status().is_success() {
        return Err(anyhow!(
            "issue/reveal failed with HTTP {}",
            reveal_resp.status()
        ));
    }
    let issuance_resp: IssuanceResponse = reveal_resp.json().await?;

    let signed_note = issuance_resp.signed_note;
    let kept_unsigned = unsigned_candidates
        .into_iter()
        .nth(closed_index)
        .ok_or_else(|| anyhow!("closed index out of range"))?;

    Ok((signed_note, kept_unsigned))
}

async fn spend_note(
    ctx: &LoadTestContext,
    signed_note: &SignedNote,
    unsigned: &UnsignedNote,
) -> Result<SpendResponse> {
    let spend_req = SpendRequest {
        note: signed_note.clone(),
    };

    let init_url = format!("{}/payment/initiate", ctx.merchant_url);
    let init_resp = ctx.client.post(&init_url).json(&spend_req).send().await?;
    if !init_resp.status().is_success() {
        return Err(anyhow!(
            "payment/initiate failed with HTTP {}",
            init_resp.status()
        ));
    }
    let challenge: SpendChallenge = init_resp.json().await?;

    let proof = generate_spend_proof(unsigned, &challenge.challenge_bits)?;

    #[derive(serde::Serialize)]
    struct PaymentCompleteRequest {
        serial: SerialNumber,
        proof: SpendProof,
    }

    let complete_req = PaymentCompleteRequest {
        serial: unsigned.data.serial,
        proof,
    };

    let complete_url = format!("{}/payment/complete", ctx.merchant_url);
    let complete_resp = ctx
        .client
        .post(&complete_url)
        .json(&complete_req)
        .send()
        .await?;
    if !complete_resp.status().is_success() {
        return Err(anyhow!(
            "payment/complete failed with HTTP {}",
            complete_resp.status()
        ));
    }
    let spend_resp: SpendResponse = complete_resp.json().await?;

    Ok(spend_resp)
}

async fn run_full_pipeline(ctx: Arc<LoadTestContext>, metrics: LoadTestMetrics) {
    let start = Instant::now();

    let result: Result<()> = async {
        let (_identity_id, theta_u, gateway_token) = register_identity(&ctx).await?;

        let (signed_note, unsigned) = issue_note(&ctx, &theta_u, &gateway_token).await?;

        let issuance_elapsed = start.elapsed().as_millis() as u64;
        metrics.with_mut(|m| {
            m.issuance_latency.record(issuance_elapsed);
            m.issuance_success += 1;
        });

        let spend_start = Instant::now();
        let spend_resp = spend_note(&ctx, &signed_note, &unsigned).await?;
        let spend_elapsed = spend_start.elapsed().as_millis() as u64;

        metrics.with_mut(|m| {
            m.spend_latency.record(spend_elapsed);
            if spend_resp.accepted {
                m.spend_success += 1;
            } else {
                m.spend_failure += 1;
            }
        });

        Ok(())
    }
    .await;

    if let Err(e) = result {
        error!("full_pipeline error: {e}");
        metrics.with_mut(|m| {
            m.issuance_failure += 1;
        });
    }

    run_lightning(metrics).await;
}

async fn run_issuance_burst(ctx: Arc<LoadTestContext>, metrics: LoadTestMetrics) {
    let start = Instant::now();

    let result: Result<()> = async {
        let (_identity_id, theta_u, gateway_token) = register_identity(&ctx).await?;
        let (_signed_note, _unsigned) = issue_note(&ctx, &theta_u, &gateway_token).await?;
        Ok(())
    }
    .await;

    let elapsed = start.elapsed().as_millis() as u64;
    metrics.with_mut(|m| {
        m.issuance_latency.record(elapsed);
        match result {
            Ok(()) => m.issuance_success += 1,
            Err(_) => m.issuance_failure += 1,
        }
    });

    if let Err(e) = result {
        error!("issuance_burst error: {e}");
    }
}

async fn run_spend_race(ctx: Arc<LoadTestContext>, metrics: LoadTestMetrics) {
    let start = Instant::now();

    let result: Result<()> = async {
        let (_identity_id, theta_u, gateway_token) = register_identity(&ctx).await?;

        let (signed_note, unsigned) = issue_note(&ctx, &theta_u, &gateway_token).await?;

        let issuance_elapsed = start.elapsed().as_millis() as u64;
        metrics.with_mut(|m| {
            m.issuance_latency.record(issuance_elapsed);
            m.issuance_success += 1;
        });

        let ctx1 = ctx.clone();
        let ctx2 = ctx.clone();
        let signed1 = signed_note.clone();
        let signed2 = signed_note;
        let unsigned1 = unsigned.data.clone();
        let unsigned2_a = unsigned.a_bits.clone();
        let unsigned2_b = unsigned.b_bits.clone();
        let unsigned2_pr = unsigned.pair_randomness.clone();

        let unsigned_for_spend1 = unsigned;

        let unsigned_for_spend2 = UnsignedNote {
            data: unsigned1,
            rho: BlindingFactor(Scalar(DalekScalar::from(0u64))),
            pair_randomness: unsigned2_pr,
            a_bits: unsigned2_a,
            b_bits: unsigned2_b,
        };

        let spend_start = Instant::now();

        let (res1, res2) = tokio::join!(
            spend_note(&ctx1, &signed1, &unsigned_for_spend1),
            spend_note(&ctx2, &signed2, &unsigned_for_spend2),
        );

        let spend_elapsed = spend_start.elapsed().as_millis() as u64;

        metrics.with_mut(|m| {
            m.spend_latency.record(spend_elapsed);
            m.double_spend_attempts += 1;

            let both_accepted = matches!((&res1, &res2), (Ok(r1), Ok(r2)) if r1.accepted && r2.accepted);
            if both_accepted {
                m.double_spend_false_negatives += 1;
                error!("DOUBLE SPEND FALSE NEGATIVE: both spends accepted for same note");
            }

            let any_ok = matches!(&res1, Ok(r) if r.accepted) || matches!(&res2, Ok(r) if r.accepted);
            if any_ok {
                m.spend_success += 1;
            }
        });

        Ok(())
    }
    .await;

    if let Err(e) = result {
        error!("spend_race error: {e}");
        metrics.with_mut(|m| {
            m.issuance_failure += 1;
        });
    }
}

async fn run_lightning(metrics: LoadTestMetrics) {
    let start = Instant::now();

    let lnd1 = LndTestClient::new(
        "LND1_HOST",
        "LND1_PORT",
        "LND1_MACAROON_PATH",
        "LND1_TLS_PATH",
    )
    .await;
    let lnd2 = LndTestClient::new(
        "LND2_HOST",
        "LND2_PORT",
        "LND2_MACAROON_PATH",
        "LND2_TLS_PATH",
    )
    .await;

    let success = match (lnd1, lnd2) {
        (Ok(sender), Ok(receiver)) => {
            match receiver.create_invoice(1000, "loadtest").await {
                Ok((payment_request, _)) => match sender.pay_invoice(&payment_request).await {
                    Ok(_) => true,
                    Err(e) => {
                        error!("Payment failed: {e}");
                        false
                    }
                },
                Err(e) => {
                    error!("Failed to create invoice: {e}");
                    false
                }
            }
        }
        _ => {
            warn!("LND clients not configured, skipping lightning test");
            return;
        }
    };

    let elapsed = start.elapsed().as_millis() as u64;
    metrics.with_mut(|m| {
        m.lightning_latency.record(elapsed);
        if success {
            m.lightning_success += 1;
        } else {
            m.lightning_failure += 1;
        }
    });
}

async fn run_workers(
    command: &Command,
    cfg: &LoadTestConfig,
    ctx: Arc<LoadTestContext>,
    metrics: LoadTestMetrics,
) {
    let mut set = JoinSet::new();
    let start = Instant::now();
    let duration = Duration::from_secs(cfg.duration_secs);
    let ramp_up = Duration::from_secs(cfg.ramp_up_secs);
    let step = if cfg.concurrency > 0 {
        ramp_up / cfg.concurrency as u32
    } else {
        Duration::from_secs(0)
    };
    let full_weight = cfg.full_pipeline_weight;
    let issuance_weight = cfg.issuance_burst_weight;
    for i in 0..cfg.concurrency {
        let metrics_clone = metrics.clone();
        let cmd = command.clone();
        let ctx = ctx.clone();
        set.spawn(async move {
            let delay = step * i as u32;
            if delay > Duration::from_secs(0) {
                tokio::time::sleep(delay).await;
            }
            loop {
                if Instant::now().duration_since(start) >= duration {
                    break;
                }
                match cmd {
                    Command::RunFull => {
                        run_full_pipeline(ctx.clone(), metrics_clone.clone()).await;
                    }
                    Command::RunIssuance => {
                        run_issuance_burst(ctx.clone(), metrics_clone.clone()).await;
                    }
                    Command::RunSpendRace => {
                        run_spend_race(ctx.clone(), metrics_clone.clone()).await;
                    }
                    Command::RunAll => {
                        let choice = rand::thread_rng().gen_range(0..100);
                        let mut acc = full_weight as u32;
                        if choice < acc {
                            run_full_pipeline(ctx.clone(), metrics_clone.clone()).await;
                        } else {
                            acc += issuance_weight as u32;
                            if choice < acc {
                                run_issuance_burst(ctx.clone(), metrics_clone.clone()).await;
                            } else {
                                run_spend_race(ctx.clone(), metrics_clone.clone()).await;
                            }
                        }
                    }
                    Command::CheckConfig => break,
                }
            }
        });
    }
    while set.join_next().await.is_some() {}
}

async fn execute_run(cli: &Cli, command: Command) -> Result<i32> {
    let base_cfg = if let Some(path) = cli.config.as_ref() {
        LoadTestConfig::from_file(path)?
    } else {
        LoadTestConfig::default()
    };
    let cfg = apply_overrides(base_cfg, cli);
    cfg.validate()?;

    let client = build_http_client(&cfg)?;

    let ctx = Arc::new(LoadTestContext {
        client,
        coordinator_url: cfg.coordinator_url.clone(),
        gateway_url: cfg.gateway_url.clone(),
        merchant_url: cfg.merchant_url.clone(),
        k: cfg.k,
        denomination: cfg.denomination_msat,
    });

    let metrics = LoadTestMetrics::new();
    let started_at = Instant::now();
    run_workers(&command, &cfg, ctx, metrics.clone()).await;
    let duration_secs = started_at.elapsed().as_secs();
    let snapshot = metrics.snapshot();
    let slo_results = evaluate_slos(&cfg, &snapshot);
    let overall_pass = slo_results
        .iter()
        .all(|r| matches!(r, crate::report::SloResult::Pass));
    let report = LoadTestReport {
        run_id: Uuid::new_v4().to_string(),
        config: cfg.clone(),
        started_at: chrono::Utc::now().to_rfc3339(),
        completed_at: chrono::Utc::now().to_rfc3339(),
        duration_secs,
        metrics: snapshot,
        slo_results,
        overall_pass,
    };
    report::print_summary(&report);
    if let Some(path) = cli.output.as_ref() {
        save_report(&report, path.as_path())
            .with_context(|| format!("failed to write report to {}", path.display()))?;
    }
    Ok(if overall_pass { 0 } else { 1 })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let code = match cli.command.clone() {
        Command::CheckConfig => {
            let base_cfg = if let Some(path) = cli.config.as_ref() {
                LoadTestConfig::from_file(path)
            } else {
                Ok(LoadTestConfig::default())
            };
            match base_cfg {
                Ok(cfg) => {
                    if let Err(err) = cfg.validate() {
                        eprintln!("config invalid: {err}");
                        2
                    } else {
                        println!("{cfg:#?}");
                        0
                    }
                }
                Err(err) => {
                    eprintln!("failed to load config: {err}");
                    2
                }
            }
        }
        Command::RunFull => match execute_run(&cli, Command::RunFull).await {
            Ok(code) => code,
            Err(err) => {
                eprintln!("error: {err:?}");
                2
            }
        },
        Command::RunIssuance => match execute_run(&cli, Command::RunIssuance).await {
            Ok(code) => code,
            Err(err) => {
                eprintln!("error: {err:?}");
                2
            }
        },
        Command::RunSpendRace => match execute_run(&cli, Command::RunSpendRace).await {
            Ok(code) => code,
            Err(err) => {
                eprintln!("error: {err:?}");
                2
            }
        },
        Command::RunAll => match execute_run(&cli, Command::RunAll).await {
            Ok(code) => code,
            Err(err) => {
                eprintln!("error: {err:?}");
                2
            }
        },
    };
    info!("exiting with code {code}");
    std::process::exit(code);
}
