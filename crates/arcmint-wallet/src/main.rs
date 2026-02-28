use anyhow::{anyhow, Result};
use arcmint_core::crypto::{
    compute_theta, hash_identity, random_scalar, BlindingFactor, Scalar, SerialNumber,
};
use arcmint_core::note::{SignedNote, UnsignedNote};
use arcmint_core::protocol::{
    IssuanceChallenge, IssuanceRequest, IssuanceResponse, IssuanceReveal, RegistrationRequest,
    RegistrationResponse, SpendChallenge, SpendProof, SpendRequest, SpendResponse,
    UnsignedNoteReveal,
};
use arcmint_core::spending::generate_spend_proof;
use clap::{Parser, Subcommand};
use curve25519_dalek::scalar::Scalar as DalekScalar;
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
struct WalletFile {
    theta_u: String,
    r_u_bytes: String,
    gateway_token: String,
    notes: Vec<StoredNote>,
}

#[derive(Serialize, Deserialize, Clone)]
struct StoredNote {
    serial: String,
    denomination: u64,
    signed_note: SignedNote,
    a_bits: Vec<u8>,
    b_bits: Vec<u8>,
    pair_randomness: Vec<[String; 2]>,
    status: String,
}

#[derive(Serialize)]
struct PaymentCompleteRequest {
    serial: SerialNumber,
    proof: SpendProof,
}

#[derive(Parser)]
#[command(name = "arcmint-wallet")]
struct Cli {
    #[arg(long, default_value_t = default_wallet_dir())]
    wallet_dir: String,
    #[arg(long)]
    coordinator_url: Option<String>,
    #[arg(long)]
    gateway_url: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Register {
        #[arg(long)]
        identity_id: String,
    },
    GenerateNote {
        #[arg(long)]
        denomination: u64,
        #[arg(long, default_value_t = 128)]
        k: usize,
    },
    ListNotes,
    Spend {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        merchant_url: String,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let wallet_path = wallet_file_path(&cli.wallet_dir);
    let client = Client::new();

    match &cli.command {
        Commands::Register { identity_id } => {
            let gateway_url = require_gateway_url(&cli)?;
            register_command(&wallet_path, identity_id, &gateway_url, &client).await
        }
        Commands::GenerateNote { denomination, k } => {
            let coordinator_url = require_coordinator_url(&cli)?;
            generate_note_command(&wallet_path, *denomination, *k, &coordinator_url, &client).await
        }
        Commands::ListNotes => {
            list_notes_command(&wallet_path)?;
            Ok(())
        }
        Commands::Spend {
            serial,
            merchant_url,
        } => spend_command(&wallet_path, serial, merchant_url, &client).await,
    }
}

async fn register_command(
    wallet_path: &Path,
    identity_id: &str,
    gateway_url: &str,
    client: &Client,
) -> Result<()> {
    if wallet_path.exists() {
        return Err(anyhow!(
            "wallet file already exists at {}",
            wallet_path.display()
        ));
    }

    let mut rng = OsRng;
    let mut r_u = random_scalar(&mut rng);
    let h_u = hash_identity(identity_id);
    let theta_u_bytes = compute_theta(&h_u, &r_u);

    let req = RegistrationRequest {
        identity_id: identity_id.to_string(),
        theta_u: theta_u_bytes.to_vec(),
        proof_of_identity: String::new(),
    };

    let url = format!("{gateway_url}/register");
    let resp = client.post(&url).json(&req).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("registration failed with HTTP {}", resp.status()));
    }
    let reg_resp: RegistrationResponse = resp.json().await?;

    let theta_u_hex = hex::encode(theta_u_bytes);
    let r_u_hex = {
        let bytes = r_u.0.to_bytes();
        hex::encode(bytes)
    };

    r_u.0.zeroize();

    let wallet = WalletFile {
        theta_u: theta_u_hex,
        r_u_bytes: r_u_hex,
        gateway_token: reg_resp.gateway_token,
        notes: Vec::new(),
    };

    save_wallet(wallet_path, &wallet)?;

    Ok(())
}

async fn generate_note_command(
    wallet_path: &Path,
    denomination: u64,
    k: usize,
    coordinator_url: &str,
    client: &Client,
) -> Result<()> {
    let mut wallet = load_wallet(wallet_path)?;

    let theta_bytes = hex::decode(&wallet.theta_u)?;
    if theta_bytes.len() != 32 {
        return Err(anyhow!("invalid theta_u length in wallet"));
    }
    let mut theta_arr = [0u8; 32];
    theta_arr.copy_from_slice(&theta_bytes);

    let mut rng = OsRng;
    let mut unsigned_candidates = Vec::with_capacity(k);
    let mut blinded_candidates = Vec::with_capacity(k);

    for _ in 0..k {
        let unsigned =
            arcmint_core::note::generate_note_candidate(&theta_arr, denomination, k, &mut rng)?;
        blinded_candidates.push(unsigned.data.clone());
        unsigned_candidates.push(unsigned);
    }

    let issue_req = IssuanceRequest {
        blinded_candidates,
        gateway_token: wallet.gateway_token.clone(),
    };

    let begin_url = format!("{coordinator_url}/issue/begin");
    let begin_resp = client.post(&begin_url).json(&issue_req).send().await?;
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
    for idx in open_indices {
        let unsigned = &unsigned_candidates[idx];
        let rho_bytes = vec![0u8; 32];
        let mut pair_randomness = Vec::with_capacity(unsigned.pair_randomness.len());
        for (ra, rb) in &unsigned.pair_randomness {
            let ra_bytes = ra.0.to_bytes().to_vec();
            let rb_bytes = rb.0.to_bytes().to_vec();
            pair_randomness.push((ra_bytes, rb_bytes));
        }
        let reveal = UnsignedNoteReveal {
            index: idx,
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

    let reveal_url = format!("{coordinator_url}/issue/reveal");
    let reveal_resp = client.post(&reveal_url).json(&reveal_req).send().await?;
    if !reveal_resp.status().is_success() {
        return Err(anyhow!(
            "issue/reveal failed with HTTP {}",
            reveal_resp.status()
        ));
    }
    let issuance_resp: IssuanceResponse = reveal_resp.json().await?;

    let signed_note = issuance_resp.signed_note;
    let kept_unsigned = unsigned_candidates
        .get(closed_index)
        .ok_or_else(|| anyhow!("closed index out of range"))?;

    if signed_note.data.serial != kept_unsigned.data.serial {
        return Err(anyhow!(
            "serial mismatch between signed note and kept candidate"
        ));
    }

    let serial_hex = hex::encode(signed_note.data.serial.0);
    let mut pair_randomness_hex = Vec::with_capacity(kept_unsigned.pair_randomness.len());
    for (ra, rb) in &kept_unsigned.pair_randomness {
        let ra_hex = hex::encode(ra.0.to_bytes());
        let rb_hex = hex::encode(rb.0.to_bytes());
        pair_randomness_hex.push([ra_hex, rb_hex]);
    }

    let stored = StoredNote {
        serial: serial_hex,
        denomination,
        signed_note,
        a_bits: kept_unsigned.a_bits.clone(),
        b_bits: kept_unsigned.b_bits.clone(),
        pair_randomness: pair_randomness_hex,
        status: "Unspent".to_string(),
    };

    wallet.notes.push(stored);
    save_wallet(wallet_path, &wallet)?;

    Ok(())
}

fn list_notes_command(wallet_path: &Path) -> Result<()> {
    let wallet = load_wallet(wallet_path)?;
    for note in wallet.notes {
        println!(
            "serial={} denom={} status={}",
            note.serial, note.denomination, note.status
        );
    }
    Ok(())
}

async fn spend_command(
    wallet_path: &Path,
    serial: &str,
    merchant_url: &str,
    client: &Client,
) -> Result<()> {
    let mut wallet = load_wallet(wallet_path)?;

    let pos = wallet
        .notes
        .iter()
        .position(|n| n.serial.eq_ignore_ascii_case(serial))
        .ok_or_else(|| anyhow!("note with serial {serial} not found"))?;

    if wallet.notes[pos].status == "Spent" {
        return Err(anyhow!("note already marked as spent"));
    }
    if wallet.notes[pos].status == "PendingSpend" {
        return Err(anyhow!(
            "note is in PendingSpend state — it may have already been revealed to a merchant; treat as potentially spent"
        ));
    }

    let stored = wallet.notes[pos].clone();

    let spend_req = SpendRequest {
        note: stored.signed_note.clone(),
    };

    let init_url = format!("{merchant_url}/payment/initiate");
    let init_resp = client.post(&init_url).json(&spend_req).send().await?;
    if !init_resp.status().is_success() {
        return Err(anyhow!(
            "payment/initiate failed with HTTP {}",
            init_resp.status()
        ));
    }
    let challenge: SpendChallenge = init_resp.json().await?;

    let mut pair_randomness = Vec::with_capacity(stored.pair_randomness.len());
    for pair in &stored.pair_randomness {
        let ra_bytes = hex::decode(&pair[0])?;
        let rb_bytes = hex::decode(&pair[1])?;
        if ra_bytes.len() != 32 || rb_bytes.len() != 32 {
            return Err(anyhow!("invalid randomness length for stored note"));
        }
        let mut ra_arr = [0u8; 32];
        ra_arr.copy_from_slice(&ra_bytes);
        let mut rb_arr = [0u8; 32];
        rb_arr.copy_from_slice(&rb_bytes);
        let ra = Scalar(DalekScalar::from_bytes_mod_order(ra_arr));
        let rb = Scalar(DalekScalar::from_bytes_mod_order(rb_arr));
        pair_randomness.push((ra, rb));
    }

    let zero_scalar = Scalar(DalekScalar::from(0u64));
    let zero_blinding = BlindingFactor(zero_scalar);

    let unsigned = UnsignedNote {
        data: stored.signed_note.data.clone(),
        rho: zero_blinding,
        pair_randomness,
        a_bits: stored.a_bits.clone(),
        b_bits: stored.b_bits.clone(),
    };

    let proof = generate_spend_proof(&unsigned, &challenge.challenge_bits)?;

    wallet.notes[pos].status = "PendingSpend".to_string();
    save_wallet(wallet_path, &wallet)?;

    let serial_bytes = hex::decode(&stored.serial)?;
    if serial_bytes.len() != 32 {
        return Err(anyhow!("invalid serial length for stored note"));
    }
    let mut serial_arr = [0u8; 32];
    serial_arr.copy_from_slice(&serial_bytes);
    let serial_value = SerialNumber(serial_arr);

    let complete_req = PaymentCompleteRequest {
        serial: serial_value,
        proof: proof.clone(),
    };

    let complete_url = format!("{merchant_url}/payment/complete");
    let complete_result = client.post(&complete_url).json(&complete_req).send().await;

    match complete_result {
        Ok(complete_resp) => {
            if !complete_resp.status().is_success() {
                return Err(anyhow!(
                    "payment/complete failed with HTTP {}; note remains in PendingSpend state — treat as potentially spent",
                    complete_resp.status()
                ));
            }
            let spend_resp: SpendResponse = complete_resp.json().await?;

            if spend_resp.accepted {
                wallet.notes[pos].status = "Spent".to_string();
            } else {
                wallet.notes[pos].status = "Unspent".to_string();
            }
            save_wallet(wallet_path, &wallet)?;
        }
        Err(e) => {
            return Err(anyhow!(
                "network error during payment/complete: {e}; note remains in PendingSpend state — treat as potentially spent"
            ));
        }
    }

    Ok(())
}

fn wallet_file_path(dir: &str) -> PathBuf {
    let mut path = PathBuf::from(dir);
    path.push("wallet.json");
    path
}

fn default_wallet_dir() -> String {
    if let Ok(home) = env::var("HOME") {
        let mut path = PathBuf::from(home);
        path.push(".arcmint");
        return path.to_string_lossy().into_owned();
    }
    if let Ok(profile) = env::var("USERPROFILE") {
        let mut path = PathBuf::from(profile);
        path.push(".arcmint");
        return path.to_string_lossy().into_owned();
    }
    ".arcmint".to_string()
}

fn save_wallet(path: &Path, wallet: &WalletFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(wallet)?;

    let tmp_path = path.with_extension("json.tmp");
    let mut file = fs::File::create(&tmp_path)?;
    file.write_all(&json)?;
    file.sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&tmp_path, perms)?;
    }

    fs::rename(&tmp_path, path)?;

    Ok(())
}

fn load_wallet(path: &Path) -> Result<WalletFile> {
    let data = fs::read(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path)?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            eprintln!("warning: wallet file permissions are {mode:o}, expected 0600");
        }
    }

    let wallet: WalletFile = serde_json::from_slice(&data)?;
    Ok(wallet)
}

fn require_coordinator_url(cli: &Cli) -> Result<String> {
    if let Some(url) = &cli.coordinator_url {
        return Ok(url.clone());
    }
    if let Ok(env_url) = env::var("COORDINATOR_URL") {
        return Ok(env_url);
    }
    Err(anyhow!(
        "--coordinator-url flag or COORDINATOR_URL env var is required"
    ))
}

fn require_gateway_url(cli: &Cli) -> Result<String> {
    if let Some(url) = &cli.gateway_url {
        return Ok(url.clone());
    }
    if let Ok(env_url) = env::var("GATEWAY_URL") {
        return Ok(env_url);
    }
    Err(anyhow!(
        "--gateway-url flag or GATEWAY_URL env var is required"
    ))
}
