use arcmint_core::dkg::state::CeremonyPhase;
use arcmint_core::dkg::types::CeremonyConfig;
use arcmint_core::dkg::types::ParticipantId;
use arcmint_core::tls::load_tls_client_config;
use clap::Parser;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_rustls::rustls::ClientConfig;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(name = "dkg_participant")]
struct Cli {
    #[arg(long)]
    coordinator_url: String,

    #[arg(long)]
    participant_id: String,

    #[arg(long)]
    operator_token: String,

    #[arg(long)]
    threshold: Option<u16>,

    #[arg(long)]
    signers: Option<u16>,

    #[arg(long)]
    participant_ids: Option<String>,

    #[arg(long)]
    output_dir: PathBuf,

    #[arg(long)]
    ca_cert: PathBuf,

    #[arg(long)]
    create_ceremony: bool,

    #[arg(long)]
    all_operator_tokens: String,
}

#[derive(Deserialize)]
struct CreateCeremonyResponse {
    ceremony_id: String,
}

#[derive(Deserialize)]
struct StatusResponse {
    phase: CeremonyPhase,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();

    let cli = Cli::parse();

    let _participant_id = ParticipantId(cli.participant_id.clone());

    let _all_tokens: HashMap<String, String> =
        serde_json::from_str(&cli.all_operator_tokens).expect("invalid all-operator-tokens JSON");

    let tls_config: ClientConfig = load_tls_client_config(cli.ca_cert.as_path(), None, None)
        .expect("failed to build TLS client config for DKG");

    let client = Client::builder()
        .use_preconfigured_tls(Arc::new(tls_config))
        .build()?;

    if cli.create_ceremony {
        let threshold = cli
            .threshold
            .expect("threshold must be set when creating ceremony");
        let max_signers = cli
            .signers
            .expect("signers must be set when creating ceremony");
        let participant_ids_str = cli
            .participant_ids
            .as_ref()
            .expect("participant-ids must be set when creating ceremony");
        let ids: Vec<ParticipantId> = participant_ids_str
            .split(',')
            .map(|s| ParticipantId(s.to_string()))
            .collect();

        let config = CeremonyConfig {
            ceremony_id: String::new(),
            threshold,
            max_signers,
            participants: ids,
            round_timeout_secs: 600,
        };

        let url = format!("{}/ceremony/create", cli.coordinator_url);
        let res = client
            .post(&url)
            .header("X-Operator-Token", &cli.operator_token)
            .json(&config)
            .send()
            .await?;
        if !res.status().is_success() {
            error!("failed to create ceremony: {}", res.status());
            return Err("failed to create ceremony".into());
        }
        let body: CreateCeremonyResponse = res.json().await?;
        info!("Created ceremony with id {}", body.ceremony_id);
    }

    let join_url = format!("{}/ceremony/join", cli.coordinator_url);
    let join_res = client
        .post(&join_url)
        .header("X-Operator-Token", &cli.operator_token)
        .send()
        .await?;
    if !join_res.status().is_success() {
        error!("failed to join ceremony: {}", join_res.status());
        return Err("failed to join ceremony".into());
    }

    // wait for Round1
    let status_url = format!("{}/ceremony/status", cli.coordinator_url);
    let status_deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if Instant::now() > status_deadline {
            error!("timeout waiting for Round1 phase");
            return Err("timeout waiting for Round1".into());
        }
        let res = client
            .get(&status_url)
            .header("X-Operator-Token", &cli.operator_token)
            .send()
            .await?;
        if res.status().is_success() {
            let status: StatusResponse = res.json().await?;
            if matches!(status.phase, CeremonyPhase::Round1 { .. }) {
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // round1
    let round1_packages_url = format!("{}/ceremony/round1/packages", cli.coordinator_url);
    let res = client
        .get(&round1_packages_url)
        .header("X-Operator-Token", &cli.operator_token)
        .send()
        .await?;
    if !res.status().is_success() {
        error!("failed to get round1 packages: {}", res.status());
        return Err("failed to get round1 packages".into());
    }
    let _: serde_json::Value = res.json().await?;

    // NOTE: placeholder stubs for DKG round1/2/3 logic – the actual FROST DKG
    // integration (keys::dkg::part1/part2/part3) and encryption of shares
    // will be wired in once available. For now, exit cleanly to keep the
    // binary compiling without warnings.

    Ok(())
}
