use arcmint_core::frost_ops::distribute_dev_keys;
use clap::Parser;
use rand::rngs::OsRng;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser)]
#[command(
    name = "keygen",
    about = "Dev FROST key generator for ArcMint federation"
)]
struct Args {
    #[arg(long)]
    threshold: u16,

    #[arg(long)]
    signers: u16,

    #[arg(long)]
    output_dir: PathBuf,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let args = Args::parse();

    if args.threshold == 0 {
        anyhow::bail!("threshold must be at least 1");
    }
    if args.signers == 0 {
        anyhow::bail!("signers must be at least 1");
    }
    if args.threshold > args.signers {
        anyhow::bail!("threshold cannot exceed signers");
    }

    let mut rng = OsRng;
    distribute_dev_keys(args.threshold, args.signers, &args.output_dir, &mut rng)?;

    info!(
        "Generated dev keys for {} signers (threshold={}) in {}",
        args.signers,
        args.threshold,
        args.output_dir.display()
    );

    Ok(())
}
