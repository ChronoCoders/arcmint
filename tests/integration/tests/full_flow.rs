use anyhow::Result;
use arcmint_core::crypto::{compute_theta, hash_identity, Scalar, SerialNumber};
use arcmint_core::note::{generate_note_candidate, UnsignedNote};
use arcmint_core::protocol::{
    AuditResponse, IssuanceChallenge, IssuanceRequest, IssuanceReveal, RegistrationRequest,
    RegistrationResponse, SpendChallenge, SpendProof, SpendRequest, SpendResponse,
    UnsignedNoteReveal,
};
use arcmint_core::spending::generate_spend_proof;
use arcmint_core::tls::{
    generate_ca, generate_client_cert, generate_server_cert, load_tls_client_config,
    save_cert_bundle,
};
use curve25519_dalek::scalar::Scalar as DalekScalar;
use hex::encode as hex_encode;
use rand::rngs::OsRng;
use rand_core::RngCore;
use reqwest::Client;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arcmint_core::frost_ops::distribute_dev_keys;
use arcmint_integration::lnd::LndTestClient;
use tokio::process::Command;
use tokio::time::sleep;

struct ProcessGuard {
    child: tokio::process::Child,
}

impl ProcessGuard {
    fn new(child: tokio::process::Child) -> Self {
        ProcessGuard { child }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

#[derive(serde::Serialize)]
struct PaymentCompleteRequest {
    serial: SerialNumber,
    proof: SpendProof,
}

#[derive(serde::Deserialize)]
struct PaymentRow {
    serial: String,
    denomination: u64,
    accepted_at: i64,
}

fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("..").join("..")
}

fn binary_path(name: &str) -> PathBuf {
    let mut path = workspace_root().join("target").join("debug").join(name);
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_full_issuance_and_spend() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(300), async move {
        let base_port: u16 = 18080;
        let coordinator_port = base_port + 1;
        let signer1_port = base_port + 2;
        let signer2_port = base_port + 3;
        let signer3_port = base_port + 4;
        let gateway_port = base_port + 5;
        let merchant_port = base_port + 6;

        let mut base = workspace_root();
        base.push("target");
        base.push("integration-db");
        fs::create_dir_all(&base)?;

        let gateway_db = base.join("gateway.db");
        let merchant_db = base.join("merchant.db");
        let frost_pubkey = base.join("public_key.json");
        let certs_dir = base.join("certs");

        fs::create_dir_all(&certs_dir)?;

        let coordinator_secret = "test-coordinator-secret";
        let operator_secret = "test-operator-secret";

        let mut rng = OsRng;
        distribute_dev_keys(2, 3, &base, &mut rng)
            .expect("failed to generate dev FROST keys for integration test");

        let ca_bundle =
            generate_ca("arcmint-internal-ca").expect("failed to generate internal CA bundle");
        let ca_cert_path = certs_dir.join("ca_cert.pem");
        let ca_key_path = certs_dir.join("ca_key.pem");
        save_cert_bundle(&ca_bundle, &ca_cert_path, &ca_key_path)
            .expect("failed to save CA bundle for integration test");

        let ca_cert_pem = &ca_bundle.cert_pem;
        let ca_key_pem = &ca_bundle.key_pem;

        let signer1_bundle = generate_server_cert(
            "signer-1",
            &["signer-1"],
            &["127.0.0.1"],
            ca_cert_pem,
            ca_key_pem,
        )
        .expect("failed to generate signer-1 server cert");
        save_cert_bundle(
            &signer1_bundle,
            &certs_dir.join("signer-1_cert.pem"),
            &certs_dir.join("signer-1_key.pem"),
        )
        .expect("failed to save signer-1 server cert");

        let signer2_bundle = generate_server_cert(
            "signer-2",
            &["signer-2"],
            &["127.0.0.1"],
            ca_cert_pem,
            ca_key_pem,
        )
        .expect("failed to generate signer-2 server cert");
        save_cert_bundle(
            &signer2_bundle,
            &certs_dir.join("signer-2_cert.pem"),
            &certs_dir.join("signer-2_key.pem"),
        )
        .expect("failed to save signer-2 server cert");

        let signer3_bundle = generate_server_cert(
            "signer-3",
            &["signer-3"],
            &["127.0.0.1"],
            ca_cert_pem,
            ca_key_pem,
        )
        .expect("failed to generate signer-3 server cert");
        save_cert_bundle(
            &signer3_bundle,
            &certs_dir.join("signer-3_cert.pem"),
            &certs_dir.join("signer-3_key.pem"),
        )
        .expect("failed to save signer-3 server cert");

        let coordinator_server_bundle = generate_server_cert(
            "coordinator",
            &["coordinator"],
            &["127.0.0.1"],
            ca_cert_pem,
            ca_key_pem,
        )
        .expect("failed to generate coordinator server cert");
        save_cert_bundle(
            &coordinator_server_bundle,
            &certs_dir.join("coordinator_cert.pem"),
            &certs_dir.join("coordinator_key.pem"),
        )
        .expect("failed to save coordinator server cert");

        let gateway_server_bundle = generate_server_cert(
            "gateway",
            &["gateway"],
            &["127.0.0.1"],
            ca_cert_pem,
            ca_key_pem,
        )
        .expect("failed to generate gateway server cert");
        save_cert_bundle(
            &gateway_server_bundle,
            &certs_dir.join("gateway_cert.pem"),
            &certs_dir.join("gateway_key.pem"),
        )
        .expect("failed to save gateway server cert");

        let coordinator_client_bundle = generate_client_cert(
            "arcmint-coordinator",
            ca_cert_pem,
            ca_key_pem,
        )
        .expect("failed to generate coordinator client cert");
        save_cert_bundle(
            &coordinator_client_bundle,
            &certs_dir.join("arcmint-coordinator_cert.pem"),
            &certs_dir.join("arcmint-coordinator_key.pem"),
        )
        .expect("failed to save coordinator client cert");

        let gateway_client_bundle =
            generate_client_cert("arcmint-gateway", ca_cert_pem, ca_key_pem)
                .expect("failed to generate gateway client cert");
        save_cert_bundle(
            &gateway_client_bundle,
            &certs_dir.join("arcmint-gateway_cert.pem"),
            &certs_dir.join("arcmint-gateway_key.pem"),
        )
        .expect("failed to save gateway client cert");

        let mut processes = Vec::new();

        let signer_bin = binary_path("arcmint-federation");

        let mut signer1_cmd = Command::new(&signer_bin);
        signer1_cmd
            .current_dir(&base)
            .env("FEDERATION_PORT", signer1_port.to_string())
            .env("FEDERATION_DB", "sqlite::memory:")
            .env(
                "FROST_KEY_FILE",
                base.join("signer_1_key.json").to_string_lossy().to_string(),
            )
            .env("FROST_PUBKEY_FILE", frost_pubkey.to_string_lossy().to_string())
            .env("SIGNER_ID", "1")
            .env("COORDINATOR_SECRET", coordinator_secret)
            .env(
                "TLS_CERT_FILE",
                certs_dir
                    .join("signer-1_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "TLS_KEY_FILE",
                certs_dir
                    .join("signer-1_key.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "TLS_CA_FILE",
                ca_cert_path.to_string_lossy().to_string(),
            )
            .env("COORDINATOR_CN", "arcmint-coordinator");
        let signer1_child = signer1_cmd.spawn()?;
        processes.push(ProcessGuard::new(signer1_child));

        let mut signer2_cmd = Command::new(&signer_bin);
        signer2_cmd
            .current_dir(&base)
            .env("FEDERATION_PORT", signer2_port.to_string())
            .env("FEDERATION_DB", "sqlite::memory:")
            .env(
                "FROST_KEY_FILE",
                base.join("signer_2_key.json").to_string_lossy().to_string(),
            )
            .env("FROST_PUBKEY_FILE", frost_pubkey.to_string_lossy().to_string())
            .env("SIGNER_ID", "2")
            .env("COORDINATOR_SECRET", coordinator_secret)
            .env(
                "TLS_CERT_FILE",
                certs_dir
                    .join("signer-2_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "TLS_KEY_FILE",
                certs_dir
                    .join("signer-2_key.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "TLS_CA_FILE",
                ca_cert_path.to_string_lossy().to_string(),
            )
            .env("COORDINATOR_CN", "arcmint-coordinator");
        let signer2_child = signer2_cmd.spawn()?;
        processes.push(ProcessGuard::new(signer2_child));

        let mut signer3_cmd = Command::new(&signer_bin);
        signer3_cmd
            .current_dir(&base)
            .env("FEDERATION_PORT", signer3_port.to_string())
            .env("FEDERATION_DB", "sqlite::memory:")
            .env(
                "FROST_KEY_FILE",
                base.join("signer_3_key.json").to_string_lossy().to_string(),
            )
            .env("FROST_PUBKEY_FILE", frost_pubkey.to_string_lossy().to_string())
            .env("SIGNER_ID", "3")
            .env("COORDINATOR_SECRET", coordinator_secret)
            .env(
                "TLS_CERT_FILE",
                certs_dir
                    .join("signer-3_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "TLS_KEY_FILE",
                certs_dir
                    .join("signer-3_key.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "TLS_CA_FILE",
                ca_cert_path.to_string_lossy().to_string(),
            )
            .env("COORDINATOR_CN", "arcmint-coordinator");
        let signer3_child = signer3_cmd.spawn()?;
        processes.push(ProcessGuard::new(signer3_child));

        let tls_config =
            load_tls_client_config(ca_cert_path.as_path(), None, None).expect("client TLS config");
        let client = Client::builder()
            .use_preconfigured_tls(Arc::new(tls_config))
            .build()?;

        wait_for_health(
            &client,
            &format!("https://127.0.0.1:{signer1_port}/health"),
            Duration::from_secs(10),
        )
        .await?;

        wait_for_health(
            &client,
            &format!("https://127.0.0.1:{signer2_port}/health"),
            Duration::from_secs(10),
        )
        .await?;

        wait_for_health(
            &client,
            &format!("https://127.0.0.1:{signer3_port}/health"),
            Duration::from_secs(10),
        )
        .await?;

        let lnd_host = env::var("LND_HOST")?;
        let lnd_port = env::var("LND_PORT")?;
        let lnd_tls_cert = env::var("LND_TLS_CERT")?;
        let lnd_macaroon = env::var("LND_MACAROON")?;
        let coordinator_bin = binary_path("coordinator");
        let mut coordinator_cmd = Command::new(coordinator_bin);
        coordinator_cmd
            .env("COORDINATOR_PORT", coordinator_port.to_string())
            .env(
                "SIGNER_URLS",
                format!(
                    "https://127.0.0.1:{signer1_port},https://127.0.0.1:{signer2_port},https://127.0.0.1:{signer3_port}"
                ),
            )
            .env("FROST_PUBKEY_FILE", frost_pubkey.to_string_lossy().to_string())
            .env("COORDINATOR_SECRET", coordinator_secret)
            .env(
                "GATEWAY_RESOLVE_URL",
                format!("https://127.0.0.1:{gateway_port}/resolve"),
            )
            .env("ANCHOR_INTERVAL_SECS", "600")
            .env(
                "COORDINATOR_TLS_CERT",
                certs_dir
                    .join("coordinator_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "COORDINATOR_TLS_KEY",
                certs_dir
                    .join("coordinator_key.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "GATEWAY_CLIENT_CA",
                ca_cert_path.to_string_lossy().to_string(),
            )
            .env(
                "COORDINATOR_CLIENT_CERT",
                certs_dir
                    .join("arcmint-coordinator_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "COORDINATOR_CLIENT_KEY",
                certs_dir
                    .join("arcmint-coordinator_key.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "INTERNAL_CA_FILE",
                ca_cert_path.to_string_lossy().to_string(),
            )
            .env("GATEWAY_CN", "arcmint-gateway")
            .env("OPERATOR_SECRET", operator_secret)
            .env("LND_HOST", lnd_host)
            .env("LND_PORT", lnd_port)
            .env("LND_TLS_CERT", lnd_tls_cert)
            .env("LND_MACAROON", lnd_macaroon);
        let coordinator_child = coordinator_cmd.spawn()?;
        processes.push(ProcessGuard::new(coordinator_child));

        let gateway_bin = binary_path("arcmint-gateway");
        let mut gateway_cmd = Command::new(gateway_bin);
        gateway_cmd
            .current_dir(&base)
            .env("GATEWAY_PORT", gateway_port.to_string())
            .env("GATEWAY_DB", "sqlite::memory:")
            .env("FEDERATION_SECRET", "test-federation-secret")
            .env(
                "GATEWAY_CLIENT_CERT",
                certs_dir
                    .join("arcmint-gateway_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "GATEWAY_CLIENT_KEY",
                certs_dir
                    .join("arcmint-gateway_key.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "INTERNAL_CA_FILE",
                ca_cert_path.to_string_lossy().to_string(),
            )
            .env(
                "TLS_CERT_FILE",
                certs_dir
                    .join("gateway_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "TLS_KEY_FILE",
                certs_dir
                    .join("gateway_key.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env("ACME_DOMAIN", "")
            .env("OPERATOR_SECRET", operator_secret);
        let gateway_child = gateway_cmd.spawn()?;
        processes.push(ProcessGuard::new(gateway_child));

        wait_for_health(
            &client,
            &format!("https://127.0.0.1:{coordinator_port}/health"),
            Duration::from_secs(10),
        )
        .await?;

        wait_for_health(
            &client,
            &format!("https://127.0.0.1:{gateway_port}/health"),
            Duration::from_secs(10),
        )
        .await?;

        let merchant_bin = binary_path("arcmint-merchant");
        let mut merchant_cmd = Command::new(merchant_bin);
        merchant_cmd
            .current_dir(&base)
            .env("MERCHANT_PORT", merchant_port.to_string())
            .env("MERCHANT_DB", "sqlite::memory:")
            .env(
                "COORDINATOR_URL",
                format!("http://127.0.0.1:{coordinator_port}"),
            )
            .env("FROST_PUBKEY_FILE", frost_pubkey.to_string_lossy().to_string());
        let merchant_child = merchant_cmd.spawn()?;
        processes.push(ProcessGuard::new(merchant_child));

        wait_for_health(
            &client,
            &format!("http://127.0.0.1:{merchant_port}/health"),
            Duration::from_secs(10),
        )
        .await?;

        let mut rng = OsRng;
        let mut r_bytes = [0u8; 32];
        rng.fill_bytes(&mut r_bytes);
        let r_scalar = Scalar(DalekScalar::from_bytes_mod_order(r_bytes));

        let identity_id = "test-identity";
        let h_u = hash_identity(identity_id);
        let theta_u = compute_theta(&h_u, &r_scalar);

        let reg_req = RegistrationRequest {
            identity_id: identity_id.to_string(),
            theta_u: theta_u.to_vec(),
            proof_of_identity: String::new(),
        };

        let reg_url = format!("https://127.0.0.1:{gateway_port}/register");
        let reg_resp = client.post(reg_url).json(&reg_req).send().await?;
        assert!(
            reg_resp.status().is_success(),
            "registration failed with status {}",
            reg_resp.status()
        );
        let reg_body: RegistrationResponse = reg_resp.json().await?;
        println!("integration: registration completed");

        let k: usize = 4;
        let denomination: u64 = 1000;

        let mut unsigned_candidates: Vec<UnsignedNote> = Vec::with_capacity(k);
        let mut blinded_candidates = Vec::with_capacity(k);
        for _ in 0..k {
            let unsigned =
                generate_note_candidate(&theta_u, denomination, k, &mut rng)?;
            unsigned_candidates.push(unsigned.clone());
            blinded_candidates.push(unsigned.data.clone());
        }

        let issue_req = IssuanceRequest {
            blinded_candidates,
            gateway_token: reg_body.gateway_token,
        };

        let issue_url = format!("https://127.0.0.1:{coordinator_port}/issue/begin");
        let issue_resp = client.post(issue_url).json(&issue_req).send().await?;
        assert!(
            issue_resp.status().is_success(),
            "issue/begin failed with status {}",
            issue_resp.status()
        );
        let challenge: IssuanceChallenge = issue_resp.json().await?;
        println!("integration: issue_begin completed");

        let open_indices = challenge.open_indices.clone();
        let mut closed_index = None;
        for idx in 0..k {
            if !open_indices.contains(&idx) {
                closed_index = Some(idx);
                break;
            }
        }
        let closed_index = closed_index.expect("no closed index found");

        let mut revealed = Vec::with_capacity(open_indices.len());
        for idx in open_indices {
            let unsigned = &unsigned_candidates[idx];
            let rho_bytes = vec![0u8; 32];
            let mut pair_randomness_bytes = Vec::with_capacity(unsigned.pair_randomness.len());
            for (ra, rb) in &unsigned.pair_randomness {
                let ra_bytes = ra.0.to_bytes().to_vec();
                let rb_bytes = rb.0.to_bytes().to_vec();
                pair_randomness_bytes.push((ra_bytes, rb_bytes));
            }
            let reveal = UnsignedNoteReveal {
                index: idx,
                serial: unsigned.data.serial,
                rho_bytes,
                pair_randomness: pair_randomness_bytes,
                a_bits: unsigned.a_bits.clone(),
                b_bits: unsigned.b_bits.clone(),
            };
            revealed.push(reveal);
        }

        let reveal_req = IssuanceReveal {
            session_id: challenge.session_id,
            revealed,
        };

        let reveal_url = format!("https://127.0.0.1:{coordinator_port}/issue/reveal");
        println!("integration: sending issue_reveal");
        let reveal_resp = client.post(reveal_url).json(&reveal_req).send().await?;
        println!("integration: issue_reveal HTTP status {}", reveal_resp.status());
        assert!(
            reveal_resp.status().is_success(),
            "issue/reveal failed with status {}",
            reveal_resp.status()
        );
        let issuance: arcmint_core::protocol::IssuanceResponse =
            reveal_resp.json().await?;
        println!("integration: issue_reveal completed");

        let signed_note = issuance.signed_note;
        let kept_unsigned = unsigned_candidates
            .get(closed_index)
            .expect("closed index out of range");

        assert_eq!(
            signed_note.data.serial, kept_unsigned.data.serial,
            "serial mismatch between signed and unsigned note"
        );

        let spend_req = SpendRequest {
            note: signed_note.clone(),
        };

        let merchant_base = format!("http://127.0.0.1:{merchant_port}");
        let initiate_url = format!("{merchant_base}/payment/initiate");
        let init_resp = client.post(initiate_url).json(&spend_req).send().await?;
        assert!(
            init_resp.status().is_success(),
            "payment/initiate failed with status {}",
            init_resp.status()
        );
        let spend_challenge: SpendChallenge = init_resp.json().await?;
        println!("integration: spend_challenge completed");

        let spend_proof =
            generate_spend_proof(kept_unsigned, &spend_challenge.challenge_bits)?;

        let serial = signed_note.data.serial;
        let complete_req = PaymentCompleteRequest {
            serial,
            proof: spend_proof.clone(),
        };

        let complete_url = format!("{merchant_base}/payment/complete");
        let complete_resp = client
            .post(complete_url)
            .json(&complete_req)
            .send()
            .await?;
        assert!(
            complete_resp.status().is_success(),
            "payment/complete failed with status {}",
            complete_resp.status()
        );
        let spend_response: SpendResponse = complete_resp.json().await?;
        assert!(
            spend_response.accepted,
            "spend was not accepted: {:?}",
            spend_response.reason
        );
        println!("integration: spend_complete completed");

        let payments_url = format!("{merchant_base}/payments");
        let payments_resp = client.get(payments_url).send().await?;
        assert!(
            payments_resp.status().is_success(),
            "/payments failed with status {}",
            payments_resp.status()
        );
        let payments: Vec<PaymentRow> = payments_resp.json().await?;
        let expected_serial_hex = hex_encode(serial.0);
        let matching = payments.iter().find(|p| {
            p.denomination == denomination
                && p.serial == expected_serial_hex
                && p.accepted_at > 0
        });
        assert!(
            matching.is_some(),
            "expected payment with denomination {denomination} and serial {expected_serial_hex} not found"
        );

        let audit_url = format!("https://127.0.0.1:{coordinator_port}/audit");
        let audit_resp = client.get(audit_url).send().await?;
        assert!(
            audit_resp.status().is_success(),
            "/audit failed with status {}",
            audit_resp.status()
        );
        let audit: AuditResponse = audit_resp.json().await?;
        assert_eq!(audit.issued_count, 1);
        assert_eq!(audit.spent_count, 1);
        assert_eq!(audit.outstanding, 0);

        drop(processes);

        let _ = fs::remove_file(gateway_db);
        let _ = fs::remove_file(merchant_db);

        Ok(())
    })
    .await?
}

async fn wait_for_health(client: &Client, url: &str, timeout: Duration) -> Result<()> {
    let start = tokio::time::Instant::now();
    loop {
        if start.elapsed() > timeout {
            anyhow::bail!("health check timeout for {url}");
        }
        let res = client.get(url).send().await;
        if let Ok(resp) = res {
            if resp.status().is_success() {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_mint_in_full_flow() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(300), async move {
        let base_port: u16 = 19080;
        let coordinator_port = base_port + 1;
        let signer1_port = base_port + 2;
        let signer2_port = base_port + 3;
        let signer3_port = base_port + 4;
        let gateway_port = base_port + 5;

        let mut base = workspace_root();
        base.push("target");
        base.push("integration-ln");
        fs::create_dir_all(&base)?;

        let frost_pubkey = base.join("public_key.json");
        let certs_dir = base.join("certs");

        fs::create_dir_all(&certs_dir)?;

        let coordinator_secret = "test-coordinator-secret";
        let operator_secret = "test-operator-secret";

        let mut rng = OsRng;
        distribute_dev_keys(2, 3, &base, &mut rng)
            .expect("failed to generate dev FROST keys for integration test");

        let ca_bundle =
            generate_ca("arcmint-internal-ca").expect("failed to generate internal CA bundle");
        let ca_cert_path = certs_dir.join("ca_cert.pem");
        let ca_key_path = certs_dir.join("ca_key.pem");
        save_cert_bundle(&ca_bundle, &ca_cert_path, &ca_key_path)
            .expect("failed to save CA bundle for integration test");

        let ca_cert_pem = &ca_bundle.cert_pem;
        let ca_key_pem = &ca_bundle.key_pem;

        let signer1_bundle = generate_server_cert(
            "signer-1",
            &["signer-1"],
            &["127.0.0.1"],
            ca_cert_pem,
            ca_key_pem,
        )
        .expect("failed to generate signer-1 server cert");
        save_cert_bundle(
            &signer1_bundle,
            &certs_dir.join("signer-1_cert.pem"),
            &certs_dir.join("signer-1_key.pem"),
        )
        .expect("failed to save signer-1 server cert");

        let signer2_bundle = generate_server_cert(
            "signer-2",
            &["signer-2"],
            &["127.0.0.1"],
            ca_cert_pem,
            ca_key_pem,
        )
        .expect("failed to generate signer-2 server cert");
        save_cert_bundle(
            &signer2_bundle,
            &certs_dir.join("signer-2_cert.pem"),
            &certs_dir.join("signer-2_key.pem"),
        )
        .expect("failed to save signer-2 server cert");

        let signer3_bundle = generate_server_cert(
            "signer-3",
            &["signer-3"],
            &["127.0.0.1"],
            ca_cert_pem,
            ca_key_pem,
        )
        .expect("failed to generate signer-3 server cert");
        save_cert_bundle(
            &signer3_bundle,
            &certs_dir.join("signer-3_cert.pem"),
            &certs_dir.join("signer-3_key.pem"),
        )
        .expect("failed to save signer-3 server cert");

        let coordinator_server_bundle = generate_server_cert(
            "coordinator",
            &["coordinator"],
            &["127.0.0.1"],
            ca_cert_pem,
            ca_key_pem,
        )
        .expect("failed to generate coordinator server cert");
        save_cert_bundle(
            &coordinator_server_bundle,
            &certs_dir.join("coordinator_cert.pem"),
            &certs_dir.join("coordinator_key.pem"),
        )
        .expect("failed to save coordinator server cert");

        let gateway_server_bundle = generate_server_cert(
            "gateway",
            &["gateway"],
            &["127.0.0.1"],
            ca_cert_pem,
            ca_key_pem,
        )
        .expect("failed to generate gateway server cert");
        save_cert_bundle(
            &gateway_server_bundle,
            &certs_dir.join("gateway_cert.pem"),
            &certs_dir.join("gateway_key.pem"),
        )
        .expect("failed to save gateway server cert");

        let coordinator_client_bundle = generate_client_cert(
            "arcmint-coordinator",
            ca_cert_pem,
            ca_key_pem,
        )
        .expect("failed to generate coordinator client cert");
        save_cert_bundle(
            &coordinator_client_bundle,
            &certs_dir.join("arcmint-coordinator_cert.pem"),
            &certs_dir.join("arcmint-coordinator_key.pem"),
        )
        .expect("failed to save coordinator client cert");

        let gateway_client_bundle =
            generate_client_cert("arcmint-gateway", ca_cert_pem, ca_key_pem)
                .expect("failed to generate gateway client cert");
        save_cert_bundle(
            &gateway_client_bundle,
            &certs_dir.join("arcmint-gateway_cert.pem"),
            &certs_dir.join("arcmint-gateway_key.pem"),
        )
        .expect("failed to save gateway client cert");

        let mut processes = Vec::new();

        let signer_bin = binary_path("arcmint-federation");

        let mut signer1_cmd = Command::new(&signer_bin);
        signer1_cmd
            .current_dir(&base)
            .env("FEDERATION_PORT", signer1_port.to_string())
            .env("FEDERATION_DB", "sqlite::memory:")
            .env(
                "FROST_KEY_FILE",
                base.join("signer_1_key.json").to_string_lossy().to_string(),
            )
            .env("FROST_PUBKEY_FILE", frost_pubkey.to_string_lossy().to_string())
            .env("SIGNER_ID", "1")
            .env("COORDINATOR_SECRET", coordinator_secret)
            .env(
                "TLS_CERT_FILE",
                certs_dir
                    .join("signer-1_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "TLS_KEY_FILE",
                certs_dir
                    .join("signer-1_key.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "TLS_CA_FILE",
                ca_cert_path.to_string_lossy().to_string(),
            )
            .env("COORDINATOR_CN", "arcmint-coordinator");
        let signer1_child = signer1_cmd.spawn()?;
        processes.push(ProcessGuard::new(signer1_child));

        let mut signer2_cmd = Command::new(&signer_bin);
        signer2_cmd
            .current_dir(&base)
            .env("FEDERATION_PORT", signer2_port.to_string())
            .env("FEDERATION_DB", "sqlite::memory:")
            .env(
                "FROST_KEY_FILE",
                base.join("signer_2_key.json").to_string_lossy().to_string(),
            )
            .env("FROST_PUBKEY_FILE", frost_pubkey.to_string_lossy().to_string())
            .env("SIGNER_ID", "2")
            .env("COORDINATOR_SECRET", coordinator_secret)
            .env(
                "TLS_CERT_FILE",
                certs_dir
                    .join("signer-2_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "TLS_KEY_FILE",
                certs_dir
                    .join("signer-2_key.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "TLS_CA_FILE",
                ca_cert_path.to_string_lossy().to_string(),
            )
            .env("COORDINATOR_CN", "arcmint-coordinator");
        let signer2_child = signer2_cmd.spawn()?;
        processes.push(ProcessGuard::new(signer2_child));

        let mut signer3_cmd = Command::new(&signer_bin);
        signer3_cmd
            .current_dir(&base)
            .env("FEDERATION_PORT", signer3_port.to_string())
            .env("FEDERATION_DB", "sqlite::memory:")
            .env(
                "FROST_KEY_FILE",
                base.join("signer_3_key.json").to_string_lossy().to_string(),
            )
            .env("FROST_PUBKEY_FILE", frost_pubkey.to_string_lossy().to_string())
            .env("SIGNER_ID", "3")
            .env("COORDINATOR_SECRET", coordinator_secret)
            .env(
                "TLS_CERT_FILE",
                certs_dir
                    .join("signer-3_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "TLS_KEY_FILE",
                certs_dir
                    .join("signer-3_key.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "TLS_CA_FILE",
                ca_cert_path.to_string_lossy().to_string(),
            )
            .env("COORDINATOR_CN", "arcmint-coordinator");
        let signer3_child = signer3_cmd.spawn()?;
        processes.push(ProcessGuard::new(signer3_child));

        let tls_config =
            load_tls_client_config(ca_cert_path.as_path(), None, None).expect("client TLS config");
        let client = Client::builder()
            .use_preconfigured_tls(Arc::new(tls_config))
            .build()?;

        wait_for_health(
            &client,
            &format!("https://127.0.0.1:{signer1_port}/health"),
            Duration::from_secs(10),
        )
        .await?;

        wait_for_health(
            &client,
            &format!("https://127.0.0.1:{signer2_port}/health"),
            Duration::from_secs(10),
        )
        .await?;

        wait_for_health(
            &client,
            &format!("https://127.0.0.1:{signer3_port}/health"),
            Duration::from_secs(10),
        )
        .await?;

        let lnd_host = env::var("LND_HOST")?;
        let lnd_port = env::var("LND_PORT")?;
        let lnd_tls_cert = env::var("LND_TLS_CERT")?;
        let lnd_macaroon = env::var("LND_MACAROON")?;
        let coordinator_bin = binary_path("coordinator");
        let mut coordinator_cmd = Command::new(coordinator_bin);
        coordinator_cmd
            .env("COORDINATOR_PORT", coordinator_port.to_string())
            .env(
                "SIGNER_URLS",
                format!(
                    "https://127.0.0.1:{signer1_port},https://127.0.0.1:{signer2_port},https://127.0.0.1:{signer3_port}"
                ),
            )
            .env("FROST_PUBKEY_FILE", frost_pubkey.to_string_lossy().to_string())
            .env("COORDINATOR_SECRET", coordinator_secret)
            .env(
                "GATEWAY_RESOLVE_URL",
                format!("https://127.0.0.1:{gateway_port}/resolve"),
            )
            .env("ANCHOR_INTERVAL_SECS", "600")
            .env(
                "COORDINATOR_TLS_CERT",
                certs_dir
                    .join("coordinator_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "COORDINATOR_TLS_KEY",
                certs_dir
                    .join("coordinator_key.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "GATEWAY_CLIENT_CA",
                ca_cert_path.to_string_lossy().to_string(),
            )
            .env(
                "COORDINATOR_CLIENT_CERT",
                certs_dir
                    .join("arcmint-coordinator_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "COORDINATOR_CLIENT_KEY",
                certs_dir
                    .join("arcmint-coordinator_key.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "INTERNAL_CA_FILE",
                ca_cert_path.to_string_lossy().to_string(),
            )
            .env("GATEWAY_CN", "arcmint-gateway")
            .env("OPERATOR_SECRET", operator_secret)
            .env("LND_HOST", lnd_host)
            .env("LND_PORT", lnd_port)
            .env("LND_TLS_CERT", lnd_tls_cert)
            .env("LND_MACAROON", lnd_macaroon);
        let coordinator_child = coordinator_cmd.spawn()?;
        processes.push(ProcessGuard::new(coordinator_child));

        let gateway_bin = binary_path("arcmint-gateway");
        let mut gateway_cmd = Command::new(gateway_bin);
        gateway_cmd
            .current_dir(&base)
            .env("GATEWAY_PORT", gateway_port.to_string())
            .env("GATEWAY_DB", "sqlite::memory:")
            .env("FEDERATION_SECRET", "test-federation-secret")
            .env(
                "GATEWAY_CLIENT_CERT",
                certs_dir
                    .join("arcmint-gateway_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "GATEWAY_CLIENT_KEY",
                certs_dir
                    .join("arcmint-gateway_key.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "INTERNAL_CA_FILE",
                ca_cert_path.to_string_lossy().to_string(),
            )
            .env(
                "TLS_CERT_FILE",
                certs_dir
                    .join("gateway_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env(
                "TLS_KEY_FILE",
                certs_dir
                    .join("gateway_key.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .env("ACME_DOMAIN", "")
            .env("OPERATOR_SECRET", operator_secret);
        let gateway_child = gateway_cmd.spawn()?;
        processes.push(ProcessGuard::new(gateway_child));

        wait_for_health(
            &client,
            &format!("https://127.0.0.1:{coordinator_port}/health"),
            Duration::from_secs(10),
        )
        .await?;

        wait_for_health(
            &client,
            &format!("https://127.0.0.1:{gateway_port}/health"),
            Duration::from_secs(10),
        )
        .await?;

        let lnd_client = LndTestClient::from_env().await?;
        let _info = lnd_client.get_info().await?;

        let mut note_hash = [0u8; 32];
        OsRng.fill_bytes(&mut note_hash);
        let denomination_msat: u64 = 100000;

        let begin_url = format!("https://127.0.0.1:{coordinator_port}/mint/in/begin");
        let begin_req = serde_json::json!({
            "denomination_msat": denomination_msat,
            "note_hash": note_hash.to_vec(),
        });
        let begin_resp = client.post(begin_url).json(&begin_req).send().await?;
        assert!(
            begin_resp.status().is_success(),
            "mint/in/begin failed with status {}",
            begin_resp.status()
        );
        let begin_body: serde_json::Value = begin_resp.json().await?;
        let payment_request = begin_body
            .get("payment_request")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let session_id = begin_body
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        let _payment = lnd_client.pay_invoice(&payment_request).await?;

        let poll_url = format!("https://127.0.0.1:{coordinator_port}/mint/in/poll");
        let start = tokio::time::Instant::now();
        let signed_note = loop {
            if start.elapsed() > Duration::from_secs(30) {
                anyhow::bail!("mint/in/poll timeout");
            }
            let poll_req = serde_json::json!({ "session_id": session_id });
            let poll_resp = client.post(&poll_url).json(&poll_req).send().await?;
            assert!(
                poll_resp.status().is_success(),
                "mint/in/poll failed with status {}",
                poll_resp.status()
            );
            let poll_body: serde_json::Value = poll_resp.json().await?;
            let status = poll_body
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if status == "ready" {
                let signed = poll_body
                    .get("signature")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                break signed;
            }
            sleep(Duration::from_millis(250)).await;
        };

        assert!(!signed_note.is_empty());

        drop(processes);

        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_smoke_load() -> Result<()> {
    let cfg_path = workspace_root().join("loadtest").join("smoke.toml");
    let contents = fs::read_to_string(&cfg_path)?;
    assert!(!contents.is_empty());
    Ok(())
}
