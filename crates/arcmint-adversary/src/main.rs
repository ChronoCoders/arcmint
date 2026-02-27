use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::runtime::Builder;
use tracing_subscriber::FmtSubscriber;

mod attacks;
mod client;
mod report;
mod runner;

use client::AdversaryClient;
use report::AdversaryReport;
use runner::AttackRunner;

#[derive(Parser, Debug)]
#[command(name = "arcmint-adversary")]
struct Cli {
    #[arg(long, default_value = "http://localhost:7000")]
    coordinator_url: String,

    #[arg(long, default_value = "http://localhost:7002")]
    gateway_url: String,

    #[arg(long, default_value = "http://localhost:7003")]
    merchant_url: String,

    #[arg(long, default_value = "http://localhost:7001")]
    signer_urls: String,

    #[arg(long)]
    ca_cert: Option<PathBuf>,

    #[arg(long)]
    output: Option<PathBuf>,

    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Debug)]
pub struct CliConfig {
    pub coordinator_url: String,
    pub gateway_url: String,
    pub merchant_url: String,
    pub signer_urls: Vec<String>,
    pub ca_cert: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub timeout_secs: u64,
    pub include_slow: bool,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    RunAll {
        #[arg(long)]
        include_slow: bool,
    },
    DoubleSpend,
    ReplayNote,
    MalformedNote,
    ChallengeManipulation,
    ForgedSignature,
    RegistryBypass,
    FloodIssuance,
    ExpiredNote,
}

fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder().finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let cli = Cli::parse();
    let signer_urls = cli
        .signer_urls
        .split(',')
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    let config = CliConfig {
        coordinator_url: cli.coordinator_url,
        gateway_url: cli.gateway_url,
        merchant_url: cli.merchant_url,
        signer_urls,
        ca_cert: cli.ca_cert,
        output: cli.output,
        timeout_secs: cli.timeout_secs,
        include_slow: false,
    };

    let rt = Builder::new_multi_thread().enable_all().build()?;

    rt.block_on(async_main(config, cli.command))
}

async fn async_main(config: CliConfig, command: Commands) -> Result<()> {
    let client = AdversaryClient::new(&config)?;
    let report = AdversaryReport::new(&config);
    let mut runner = AttackRunner {
        client,
        config,
        report,
    };

    let all_passed = match command {
        Commands::RunAll { include_slow } => runner.run_all(include_slow).await?,
        Commands::DoubleSpend => runner.run_single("double-spend", false).await?,
        Commands::ReplayNote => runner.run_single("replay-spent-note", false).await?,
        Commands::MalformedNote => {
            runner
                .run_single("malformed-note-missing-pairs", false)
                .await?
        }
        Commands::ChallengeManipulation => {
            runner.run_single("challenge-precomputation", false).await?
        }
        Commands::ForgedSignature => runner.run_single("forged-signature", false).await?,
        Commands::RegistryBypass => runner.run_single("registry-bypass", false).await?,
        Commands::FloodIssuance => runner.run_single("flood-issuance", false).await?,
        Commands::ExpiredNote => runner.run_single("expired-note", true).await?,
    };

    if !all_passed {
        std::process::exit(1);
    }

    Ok(())
}
