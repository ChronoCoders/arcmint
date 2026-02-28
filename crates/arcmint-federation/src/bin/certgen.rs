use std::path::PathBuf;

use arcmint_core::error::Result;
use arcmint_core::tls::{
    generate_ca, generate_client_cert, generate_server_cert, save_cert_bundle,
};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "certgen")]
#[command(about = "ArcMint TLS certificate generator")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Ca {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        common_name: String,
    },
    Server {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        common_name: String,
        #[arg(long, value_delimiter = ',')]
        san_dns: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        san_ip: Vec<String>,
        #[arg(long)]
        ca_cert: PathBuf,
        #[arg(long)]
        ca_key: PathBuf,
    },
    Client {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        common_name: String,
        #[arg(long)]
        ca_cert: PathBuf,
        #[arg(long)]
        ca_key: PathBuf,
    },
}

fn read_file(path: &PathBuf) -> Result<String> {
    let data = std::fs::read_to_string(path).map_err(|e| {
        arcmint_core::error::ArcMintError::CryptoError(format!(
            "failed to read {}: {e}",
            path.display()
        ))
    })?;
    Ok(data)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Ca {
            output_dir,
            common_name,
        } => {
            let bundle = generate_ca(&common_name)?;
            let cert_path = output_dir.join("ca_cert.pem");
            let key_path = output_dir.join("ca_key.pem");
            save_cert_bundle(&bundle, &cert_path, &key_path)?;
        }
        Commands::Server {
            output_dir,
            common_name,
            san_dns,
            san_ip,
            ca_cert,
            ca_key,
        } => {
            let ca_cert_pem = read_file(&ca_cert)?;
            let ca_key_pem = read_file(&ca_key)?;
            let san_dns_refs: Vec<&str> = san_dns.iter().map(String::as_str).collect();
            let san_ip_refs: Vec<&str> = san_ip.iter().map(String::as_str).collect();
            let bundle = generate_server_cert(
                &common_name,
                &san_dns_refs,
                &san_ip_refs,
                &ca_cert_pem,
                &ca_key_pem,
            )?;
            let cert_path = output_dir.join(format!("{common_name}_cert.pem"));
            let key_path = output_dir.join(format!("{common_name}_key.pem"));
            save_cert_bundle(&bundle, &cert_path, &key_path)?;
        }
        Commands::Client {
            output_dir,
            common_name,
            ca_cert,
            ca_key,
        } => {
            let ca_cert_pem = read_file(&ca_cert)?;
            let ca_key_pem = read_file(&ca_key)?;
            let bundle = generate_client_cert(&common_name, &ca_cert_pem, &ca_key_pem)?;
            let cert_path = output_dir.join(format!("{common_name}_cert.pem"));
            let key_path = output_dir.join(format!("{common_name}_key.pem"));
            save_cert_bundle(&bundle, &cert_path, &key_path)?;
        }
    }
    Ok(())
}
