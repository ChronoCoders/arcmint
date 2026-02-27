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
    bitcoin_rpc_url: String,
    bitcoin_rpc_user: String,
    bitcoin_rpc_pass: String,
}

impl LndTestClient {
    pub async fn from_env() -> Result<Self> {
        let host = env::var("LND_HOST").unwrap_or_else(|_| "localhost".to_string());
        let rest_port: u16 = env::var("LND_REST_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8080);
        let tls_cert_path = env::var("LND_TLS_CERT")?;
        let tls_bytes = fs::read(tls_cert_path)?;
        let cert = Certificate::from_pem(&tls_bytes)?;

        let macaroon_env = env::var("LND_MACAROON")?;
        let macaroon_hex = if Path::new(&macaroon_env).exists() {
            let bytes = fs::read(macaroon_env)?;
            hex_encode(bytes)
        } else {
            macaroon_env
        };

        let client = Client::builder().add_root_certificate(cert).build()?;

        let bitcoin_rpc_url =
            env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://localhost:18443".to_string());
        let bitcoin_rpc_user =
            env::var("BITCOIN_RPC_USER").unwrap_or_else(|_| "arcmint".to_string());
        let bitcoin_rpc_pass =
            env::var("BITCOIN_RPC_PASS").unwrap_or_else(|_| "arcmintpass".to_string());

        Ok(LndTestClient {
            client,
            base_url: format!("https://{host}:{rest_port}"),
            macaroon_hex,
            bitcoin_rpc_url,
            bitcoin_rpc_user,
            bitcoin_rpc_pass,
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

    pub async fn get_channel_balance(&self) -> Result<(u64, u64)> {
        let url = format!("{}/v1/balance/channels", self.base_url);
        let resp: reqwest::Response = self
            .client
            .get(url)
            .header("Grpc-Metadata-macaroon", &self.macaroon_hex)
            .send()
            .await?;
        let value: Value = resp.error_for_status()?.json::<Value>().await?;
        let local_msat = value
            .get("local_balance")
            .and_then(|b: &Value| b.get("msat"))
            .and_then(|v: &Value| v.as_str())
            .and_then(|s: &str| s.parse::<u64>().ok())
            .unwrap_or(0);
        let remote_msat = value
            .get("remote_balance")
            .and_then(|b: &Value| b.get("msat"))
            .and_then(|v: &Value| v.as_str())
            .and_then(|s: &str| s.parse::<u64>().ok())
            .unwrap_or(0);
        Ok((local_msat, remote_msat))
    }

    pub async fn mine_blocks(&self, n: u32) -> Result<()> {
        let addr = self.get_new_address().await?;
        let payload = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "mine",
            "method": "generatetoaddress",
            "params": [n, addr],
        });
        let resp: reqwest::Response = self
            .client
            .post(&self.bitcoin_rpc_url)
            .basic_auth(&self.bitcoin_rpc_user, Some(&self.bitcoin_rpc_pass))
            .json(&payload)
            .send()
            .await?;
        let _value: Value = resp.error_for_status()?.json::<Value>().await?;
        Ok(())
    }

    async fn get_new_address(&self) -> Result<String> {
        let payload = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "addr",
            "method": "getnewaddress",
            "params": [],
        });
        let resp: reqwest::Response = self
            .client
            .post(&self.bitcoin_rpc_url)
            .basic_auth(&self.bitcoin_rpc_user, Some(&self.bitcoin_rpc_pass))
            .json(&payload)
            .send()
            .await?;
        let value: Value = resp.error_for_status()?.json::<Value>().await?;
        let addr = value
            .get("result")
            .and_then(|v: &Value| v.as_str())
            .unwrap_or_default()
            .to_string();
        Ok(addr)
    }
}
