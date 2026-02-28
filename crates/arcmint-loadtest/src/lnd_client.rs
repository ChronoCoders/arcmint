use anyhow::Result;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use hex::encode as hex_encode;
use reqwest::{Certificate, Client};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::Path;

pub struct LndTestClient {
    client: Client,
    base_url: String,
    macaroon_hex: String,
}

impl LndTestClient {
    pub async fn new(host_env: &str, port_env: &str, macaroon_env: &str, tls_env: &str) -> Result<Self> {
        let host = env::var(host_env).unwrap_or_else(|_| "localhost".to_string());
        let rest_port: u16 = env::var(port_env)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8080);
        let tls_cert_path = env::var(tls_env)?;
        let tls_bytes = fs::read(tls_cert_path)?;
        let cert = Certificate::from_pem(&tls_bytes)?;

        let macaroon_path = env::var(macaroon_env)?;
        let macaroon_hex = if Path::new(&macaroon_path).exists() {
            let bytes = fs::read(macaroon_path)?;
            hex_encode(bytes)
        } else {
            macaroon_path
        };

        let client = Client::builder()
            .add_root_certificate(cert)
            .danger_accept_invalid_certs(true) // For self-signed certs in tests
            .build()?;

        Ok(LndTestClient {
            client,
            base_url: format!("https://{host}:{rest_port}"),
            macaroon_hex,
        })
    }

    pub async fn get_info(&self) -> Result<Value> {
        let url = format!("{}/v1/getinfo", self.base_url);
        let resp: reqwest::Response = self
            .client
            .get(url)
            .header("Grpc-Metadata-macaroon", &self.macaroon_hex)
            .send()
            .await?;
        let value: Value = resp.error_for_status()?.json::<Value>().await?;
        Ok(value)
    }

    pub async fn create_invoice(&self, amount_msat: u64, memo: &str) -> Result<(String, String)> {
        let url = format!("{}/v1/invoices", self.base_url);
        let body = serde_json::json!({
            "value_msat": amount_msat.to_string(),
            "memo": memo,
        });
        let resp: reqwest::Response = self
            .client
            .post(url)
            .header("Grpc-Metadata-macaroon", &self.macaroon_hex)
            .json(&body)
            .send()
            .await?;
        let value: Value = resp.error_for_status()?.json::<Value>().await?;
        let payment_request = value
            .get("payment_request")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let r_hash_b64 = value
            .get("r_hash")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let r_hash_bytes = BASE64_STANDARD.decode(r_hash_b64)?;
        let payment_hash_hex = hex_encode(r_hash_bytes);
        Ok((payment_request, payment_hash_hex))
    }

    pub async fn pay_invoice(&self, payment_request: &str) -> Result<Value> {
        let url = format!("{}/v1/channels/transactions", self.base_url);
        let body = serde_json::json!({
            "payment_request": payment_request,
        });
        let resp: reqwest::Response = self
            .client
            .post(url)
            .header("Grpc-Metadata-macaroon", &self.macaroon_hex)
            .json(&body)
            .send()
            .await?;
        let value: Value = resp.error_for_status()?.json::<Value>().await?;
        Ok(value)
    }
}
