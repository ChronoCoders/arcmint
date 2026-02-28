use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::debug;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitcoinRpcConfig {
    pub url: String,
    pub user: String,
    pub password: String,
    pub wallet_name: String,
}

#[derive(Clone)]
pub struct BitcoinRpcClient {
    client: Client,
    url: String,
    auth_header: String,
}

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: Value,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub amount_sat: u64,
    pub confirmations: u32,
    pub spendable: bool,
}

#[derive(Deserialize)]
struct RpcUtxo {
    txid: String,
    vout: u32,
    amount: f64,
    confirmations: u32,
    spendable: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TxInfo {
    pub txid: String,
    pub confirmations: u64,
    pub block_height: Option<u64>,
    pub hex: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MempoolEntryFees {
    pub base: f64,
    pub modified: f64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MempoolEntry {
    #[serde(rename = "fees")]
    pub fees: MempoolEntryFees,
    #[serde(rename = "descendantcount")]
    pub descendant_count: u64,
    #[serde(rename = "ancestorcount")]
    pub ancestor_count: u64,
}

#[derive(Deserialize)]
struct GetTransactionResult {
    txid: String,
    confirmations: Option<u64>,
    blockhash: Option<String>,
    hex: String,
}

#[derive(Deserialize)]
struct EstimateSmartFeeResult {
    feerate: Option<f64>,
}

pub struct UtxoSelector;

pub type UxtoSelector = UtxoSelector;

impl BitcoinRpcClient {
    pub fn new(config: BitcoinRpcConfig) -> Result<Self> {
        let client = Client::new();
        let base = if config.wallet_name.is_empty() {
            config.url
        } else {
            format!("{}/wallet/{}", config.url, config.wallet_name)
        };
        let credentials = format!("{}:{}", config.user, config.password);
        let encoded = BASE64_STANDARD.encode(credentials.as_bytes());
        let auth_header = format!("Basic {encoded}");
        Ok(Self {
            client,
            url: base,
            auth_header,
        })
    }

    pub async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let request = RpcRequest {
            jsonrpc: "1.1",
            id: 1,
            method,
            params,
        };
        let auth_value = HeaderValue::from_str(&self.auth_header)?;
        let response = self
            .client
            .post(&self.url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, auth_value)
            .json(&request)
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await?;
        debug!("bitcoin rpc {} status={} body={}", method, status, text);
        if !status.is_success() {
            return Err(anyhow!("bitcoin rpc http error: {status} {text}"));
        }
        let parsed: RpcResponse<T> = serde_json::from_str(&text)?;
        if let Some(err) = parsed.error {
            return Err(anyhow!("bitcoin rpc error {}: {}", err.code, err.message));
        }
        match parsed.result {
            Some(result) => Ok(result),
            None => Err(anyhow!("bitcoin rpc missing result for method {method}")),
        }
    }

    pub async fn get_block_count(&self) -> Result<u64> {
        self.call("getblockcount", json!([])).await
    }

    pub async fn get_best_block_hash(&self) -> Result<String> {
        self.call("getbestblockhash", json!([])).await
    }

    pub async fn list_unspent(&self, min_confirmations: u32) -> Result<Vec<Utxo>> {
        let rpc_utxos: Vec<RpcUtxo> = self
            .call(
                "listunspent",
                json!([
                    min_confirmations,
                    serde_json::Value::Null,
                    serde_json::Value::Null,
                    true
                ]),
            )
            .await?;
        let mut out = Vec::with_capacity(rpc_utxos.len());
        for u in rpc_utxos {
            let amount_sat = (u.amount * 100_000_000.0).round() as u64;
            out.push(Utxo {
                txid: u.txid,
                vout: u.vout,
                amount_sat,
                confirmations: u.confirmations,
                spendable: u.spendable,
            });
        }
        Ok(out)
    }

    pub async fn get_raw_mempool(&self) -> Result<Vec<String>> {
        self.call("getrawmempool", json!([false])).await
    }

    pub async fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        self.call("sendrawtransaction", json!([hex])).await
    }

    pub async fn get_transaction(&self, txid: &str) -> Result<TxInfo> {
        let tx: GetTransactionResult = self.call("gettransaction", json!([txid, true])).await?;
        let block_height = if let Some(blockhash) = tx.blockhash.clone() {
            let block: Value = self.call("getblock", json!([blockhash])).await?;
            block.get("height").and_then(|h| h.as_u64())
        } else {
            None
        };
        Ok(TxInfo {
            txid: tx.txid,
            confirmations: tx.confirmations.unwrap_or(0),
            block_height,
            hex: tx.hex,
        })
    }

    pub async fn estimate_smart_fee(&self, target_blocks: u32) -> Result<f64> {
        let result: EstimateSmartFeeResult = self
            .call("estimatesmartfee", json!([target_blocks, "conservative"]))
            .await?;
        let feerate_btc_per_kb = result
            .feerate
            .ok_or_else(|| anyhow!("missing feerate in estimatesmartfee result"))?;
        let sat_per_vbyte = feerate_btc_per_kb * 100_000_000.0 / 1000.0;
        Ok(sat_per_vbyte)
    }

    pub async fn get_mempool_entry(&self, txid: &str) -> Result<Option<MempoolEntry>> {
        let request = RpcRequest {
            jsonrpc: "1.1",
            id: 1,
            method: "getmempoolentry",
            params: json!([txid]),
        };
        let auth_value = HeaderValue::from_str(&self.auth_header)?;
        let response = self
            .client
            .post(&self.url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, auth_value)
            .json(&request)
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await?;
        debug!(
            "bitcoin rpc getmempoolentry status={} body={}",
            status, text
        );
        if !status.is_success() {
            return Err(anyhow!("bitcoin rpc http error: {status} {text}"));
        }
        let parsed: RpcResponse<MempoolEntry> = serde_json::from_str(&text)?;
        if let Some(err) = parsed.error {
            if err.code == -5 {
                return Ok(None);
            }
            return Err(anyhow!("bitcoin rpc error {}: {}", err.code, err.message));
        }
        match parsed.result {
            Some(entry) => Ok(Some(entry)),
            None => Ok(None),
        }
    }

    pub async fn bump_fee(&self, txid: &str) -> Result<String> {
        self.call("bumpfee", json!([txid])).await
    }
}

impl UtxoSelector {
    pub fn select_utxo(utxos: &[Utxo], required_sat: u64) -> Result<Utxo> {
        let mut best: Option<&Utxo> = None;
        for utxo in utxos {
            if utxo.confirmations < 1 {
                continue;
            }
            if utxo.amount_sat < required_sat {
                continue;
            }
            match best {
                None => {
                    best = Some(utxo);
                }
                Some(current) => {
                    if utxo.amount_sat < current.amount_sat {
                        best = Some(utxo);
                    }
                }
            }
        }
        match best {
            Some(u) => Ok(u.clone()),
            None => Err(anyhow!("no suitable UTXO found")),
        }
    }
}
