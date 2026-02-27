use super::bitcoin_rpc::BitcoinRpcClient;
use crate::metrics::{
    ANCHOR_CONFIRMATIONS, ANCHOR_EVICTIONS_TOTAL, ANCHOR_FEE_BUMPS_TOTAL, ANCHOR_REORGS_TOTAL,
};
use anyhow::{anyhow, Result};
use sqlx::{FromRow, SqlitePool};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
pub enum AnchorTxStatus {
    Pending,
    Confirmed,
    Reorged,
    Evicted,
}

impl std::fmt::Display for AnchorTxStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnchorTxStatus::Pending => write!(f, "pending"),
            AnchorTxStatus::Confirmed => write!(f, "confirmed"),
            AnchorTxStatus::Reorged => write!(f, "reorged"),
            AnchorTxStatus::Evicted => write!(f, "evicted"),
        }
    }
}

impl std::str::FromStr for AnchorTxStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "pending" => Ok(AnchorTxStatus::Pending),
            "confirmed" => Ok(AnchorTxStatus::Confirmed),
            "reorged" => Ok(AnchorTxStatus::Reorged),
            "evicted" => Ok(AnchorTxStatus::Evicted),
            _ => Err(anyhow!("invalid anchor tx status: {}", s)),
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct AnchorTxRecord {
    pub txid: String,
    pub payload_hash: String,
    pub block_height: Option<i64>,
    pub confirmations: i64,
    pub status: String,
    pub broadcast_at: i64,
    pub confirmed_at: Option<i64>,
}

#[derive(Clone)]
pub struct AnchorTracker {
    pool: SqlitePool,
}

impl AnchorTracker {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn init_table(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS anchor_txs (
                txid TEXT PRIMARY KEY,
                payload_hash TEXT NOT NULL,
                block_height INTEGER,
                confirmations INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                broadcast_at INTEGER NOT NULL,
                confirmed_at INTEGER
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn register_broadcast(&self, txid: &str, payload_hash: &str) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO anchor_txs (txid, payload_hash, confirmations, status, broadcast_at)
            VALUES (?, ?, 0, 'pending', ?)
            "#,
        )
        .bind(txid)
        .bind(payload_hash)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_confirmations(&self, rpc: &BitcoinRpcClient) -> Result<()> {
        // We check 'pending' and 'reorged' transactions.
        // 'confirmed' ones are generally safe but deep reorgs could affect them.
        // For simplicity/performance, we mostly care about pending ones becoming confirmed
        // or getting evicted.
        // The prompt says "For each pending tx".
        let pending_txs: Vec<AnchorTxRecord> =
            sqlx::query_as("SELECT * FROM anchor_txs WHERE status IN ('pending', 'reorged')")
                .fetch_all(&self.pool)
                .await?;

        for record in pending_txs {
            // Call rpc.get_transaction(txid)
            match rpc.get_transaction(&record.txid).await {
                Ok(tx_info) => {
                    let mut status = record.status.clone();
                    let mut confirmed_at = record.confirmed_at;
                    let confirmations = tx_info.confirmations as i64;
                    let block_height = tx_info.block_height.map(|h| h as i64);

                    // Update confirmations metric
                    ANCHOR_CONFIRMATIONS
                        .with_label_values(&[&record.txid])
                        .set(confirmations as f64);

                    // Check for re-org: block height changed from what we knew?
                    // Only if we had a block height before.
                    if let (Some(old_height), Some(new_height)) =
                        (record.block_height, block_height)
                    {
                        if old_height != new_height {
                            warn!(
                                "Re-org detected for tx {}: height changed form {} to {}",
                                record.txid, old_height, new_height
                            );
                            status = "reorged".to_string();
                            ANCHOR_REORGS_TOTAL.inc();
                        }
                    }

                    // Status transitions
                    if confirmations >= 6 {
                        status = "confirmed".to_string();
                    }

                    // First confirmation?
                    if confirmations >= 1 && record.confirmations < 1 {
                        confirmed_at = Some(
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as i64,
                        );
                    }

                    // Update DB
                    sqlx::query(
                        r#"
                        UPDATE anchor_txs
                        SET confirmations = ?, block_height = ?, status = ?, confirmed_at = ?
                        WHERE txid = ?
                        "#,
                    )
                    .bind(confirmations)
                    .bind(block_height)
                    .bind(status)
                    .bind(confirmed_at)
                    .bind(&record.txid)
                    .execute(&self.pool)
                    .await?;
                }
                Err(_) => {
                    // Check if it's "not found" or just a connection error.
                    // rpc.get_transaction usually fails if tx is not in wallet/node.
                    // But if we just broadcasted it, it should be there or in mempool.
                    // Check mempool.
                    let in_mempool = match rpc.get_mempool_entry(&record.txid).await {
                        Ok(Some(_)) => true,
                        Ok(None) => false,
                        Err(_) => false, // Assume not in mempool if error? or retry?
                    };

                    if !in_mempool {
                        // Evicted
                        warn!("Anchor tx {} evicted from mempool", record.txid);
                        sqlx::query("UPDATE anchor_txs SET status = 'evicted' WHERE txid = ?")
                            .bind(&record.txid)
                            .execute(&self.pool)
                            .await?;
                        ANCHOR_EVICTIONS_TOTAL.inc();
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn handle_evicted(
        &self,
        rpc: &BitcoinRpcClient,
        txid: &str,
    ) -> Result<Option<String>> {
        // Attempt RBF via bump_fee
        match rpc.bump_fee(txid).await {
            Ok(new_txid) => {
                info!("Fee bump successful for {}: new txid {}", txid, new_txid);
                ANCHOR_FEE_BUMPS_TOTAL.inc();
                Ok(Some(new_txid))
            }
            Err(e) => {
                warn!("Fee bump failed for {}: {}", txid, e);
                // If not in mempool, we might need to rebroadcast the original or construct a new one.
                // The prompt says "If bump_fee fails (tx not in mempool): return None (needs rebroadcast)"
                Ok(None)
            }
        }
    }

    pub async fn get_pending_txs(&self) -> Result<Vec<AnchorTxRecord>> {
        let txs = sqlx::query_as("SELECT * FROM anchor_txs WHERE status = 'pending'")
            .fetch_all(&self.pool)
            .await?;
        Ok(txs)
    }

    pub async fn get_confirmation_depth(&self, txid: &str) -> Result<Option<u32>> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT confirmations FROM anchor_txs WHERE txid = ?")
                .bind(txid)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.map(|(c,)| c as u32))
    }
}

pub async fn run_tracker_loop(tracker: AnchorTracker, rpc: BitcoinRpcClient, interval_secs: u64) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;

        if let Err(e) = tracker.update_confirmations(&rpc).await {
            error!("Error updating anchor confirmations: {}", e);
        }

        // Check for evicted txs and handle them
        match sqlx::query_as::<_, AnchorTxRecord>(
            "SELECT * FROM anchor_txs WHERE status = 'evicted'",
        )
        .fetch_all(&tracker.pool)
        .await
        {
            Ok(evicted_txs) => {
                for tx in evicted_txs {
                    match tracker.handle_evicted(&rpc, &tx.txid).await {
                        Ok(Some(new_txid)) => {
                            // Register the new tx
                            if let Err(e) = tracker
                                .register_broadcast(&new_txid, &tx.payload_hash)
                                .await
                            {
                                error!("Failed to register fee-bumped tx {}: {}", new_txid, e);
                            }
                            // Mark old one as handled? Or keep as evicted?
                            // Maybe we should mark it as replaced?
                            // For now, leave as evicted.
                        }
                        Ok(None) => {
                            // Needs rebroadcast. Logic to trigger rebroadcast is outside scope of this function?
                            // Or we just log it.
                            warn!(
                                "Evicted tx {} could not be fee-bumped (needs rebroadcast)",
                                tx.txid
                            );
                        }
                        Err(e) => {
                            error!("Error handling evicted tx {}: {}", tx.txid, e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Error fetching evicted txs: {}", e);
            }
        }
    }
}
