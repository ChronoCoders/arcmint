use crate::crypto::SerialNumber;
use crate::error::{ArcMintError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};

#[derive(Clone)]
pub struct IssuedRegistry {
    pool: SqlitePool,
}

impl IssuedRegistry {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn init_schema(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS issued_notes (
                 serial TEXT PRIMARY KEY,
                 denomination INTEGER NOT NULL,
                 issued_at INTEGER NOT NULL
             )",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert(&self, serial: &SerialNumber, denomination: u64) -> Result<()> {
        let serial_hex = hex::encode(serial.0);
        let issued_at = current_timestamp();

        sqlx::query(
            "INSERT INTO issued_notes (serial, denomination, issued_at)
              VALUES (?1, ?2, ?3)",
        )
        .bind(serial_hex)
        .bind(denomination as i64)
        .bind(issued_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn contains(&self, serial: &SerialNumber) -> Result<bool> {
        let serial_hex = hex::encode(serial.0);

        let row = sqlx::query("SELECT 1 FROM issued_notes WHERE serial = ?1 LIMIT 1")
            .bind(serial_hex)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.is_some())
    }

    pub async fn all_serials(&self) -> Result<Vec<SerialNumber>> {
        let rows = sqlx::query("SELECT serial FROM issued_notes ORDER BY serial")
            .fetch_all(&self.pool)
            .await?;

        let mut serials = Vec::with_capacity(rows.len());
        for row in rows {
            let s: String = row.try_get("serial")?;
            let bytes = hex::decode(&s).map_err(|e| {
                ArcMintError::RegistryError(format!("invalid serial hex in DB: {e}"))
            })?;
            if bytes.len() != 32 {
                return Err(ArcMintError::RegistryError(
                    "invalid serial length in DB".to_string(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            serials.push(SerialNumber(arr));
        }

        Ok(serials)
    }

    pub async fn count(&self) -> Result<u64> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM issued_notes")
            .fetch_one(&self.pool)
            .await?;

        let cnt: i64 = row.try_get("cnt")?;
        if cnt < 0 {
            return Err(ArcMintError::RegistryError(
                "negative count in issued_notes".to_string(),
            ));
        }

        Ok(cnt as u64)
    }
}

#[derive(Clone)]
pub struct SpentRegistry {
    pool: SqlitePool,
}

impl SpentRegistry {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn init_schema(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS spent_notes (
                 serial TEXT PRIMARY KEY,
                 challenge_1 TEXT NOT NULL,
                 challenge_2 TEXT,
                 theta_u TEXT,
                 spent_at INTEGER NOT NULL
             )",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_pending(&self, serial: &SerialNumber, challenge: &[u8]) -> Result<()> {
        let serial_hex = hex::encode(serial.0);
        let challenge_hex = hex::encode(challenge);
        let spent_at = current_timestamp();

        sqlx::query(
            "INSERT INTO spent_notes (serial, challenge_1, challenge_2, theta_u, spent_at)
              VALUES (?1, ?2, NULL, NULL, ?3)",
        )
        .bind(serial_hex)
        .bind(challenge_hex)
        .bind(spent_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn insert_second_spend(
        &self,
        serial: &SerialNumber,
        challenge_2: &[u8],
        theta_u: &[u8; 32],
    ) -> Result<Option<([u8; 32], Vec<u8>, Vec<u8>)>> {
        let serial_hex = hex::encode(serial.0);
        let challenge_2_hex = hex::encode(challenge_2);
        let theta_hex = hex::encode(theta_u);
        let spent_at = current_timestamp();

        let mut conn = self.pool.acquire().await?;

        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *conn)
            .await?;

        let row = sqlx::query(
            "SELECT challenge_1, challenge_2, theta_u FROM spent_notes WHERE serial = ?1",
        )
        .bind(&serial_hex)
        .fetch_optional(&mut *conn)
        .await;

        let row = match row {
            Ok(r) => r,
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(e.into());
            }
        };

        match row {
            Some(row) => {
                let process = async {
                    let challenge_1_hex: String = row.try_get("challenge_1")?;
                    let existing_challenge_2: Option<String> = row.try_get("challenge_2")?;
                    let existing_theta_hex: Option<String> = row.try_get("theta_u")?;

                    let challenge_1_bytes = hex::decode(&challenge_1_hex).map_err(|e| {
                        ArcMintError::RegistryError(format!("invalid challenge_1 hex in DB: {e}"))
                    })?;

                    let theta_bytes = if let Some(ref existing_hex) = existing_theta_hex {
                        let decoded = hex::decode(existing_hex).map_err(|e| {
                            ArcMintError::RegistryError(format!(
                                "invalid theta_u hex in DB: {e}"
                            ))
                        })?;
                        if decoded.len() != 32 {
                            return Err::<_, crate::error::ArcMintError>(
                                ArcMintError::RegistryError(
                                    "invalid theta_u length in DB".to_string(),
                                ),
                            );
                        }
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&decoded);
                        arr
                    } else {
                        *theta_u
                    };

                    if existing_challenge_2.is_none() || existing_theta_hex.is_none() {
                        sqlx::query(
                            "UPDATE spent_notes
                              SET challenge_2 = ?1, theta_u = ?2, spent_at = ?3
                              WHERE serial = ?4
                                AND challenge_2 IS NULL",
                        )
                        .bind(&challenge_2_hex)
                        .bind(&theta_hex)
                        .bind(spent_at)
                        .bind(&serial_hex)
                        .execute(&mut *conn)
                        .await?;
                    }

                    Ok((theta_bytes, challenge_1_bytes, challenge_2.to_vec()))
                };

                match process.await {
                    Ok(result) => {
                        sqlx::query("COMMIT").execute(&mut *conn).await?;
                        Ok(Some(result))
                    }
                    Err(e) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        Err(e)
                    }
                }
            }
            None => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(ArcMintError::RegistryError(
                    "cannot record second spend for unknown serial; first spend must be recorded first"
                        .to_string(),
                ))
            }
        }
    }

    pub async fn is_spent(&self, serial: &SerialNumber) -> Result<bool> {
        let serial_hex = hex::encode(serial.0);

        let row = sqlx::query("SELECT 1 FROM spent_notes WHERE serial = ?1 LIMIT 1")
            .bind(serial_hex)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.is_some())
    }

    pub async fn count(&self) -> Result<u64> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM spent_notes")
            .fetch_one(&self.pool)
            .await?;

        let cnt: i64 = row.try_get("cnt")?;
        if cnt < 0 {
            return Err(ArcMintError::RegistryError(
                "negative count in spent_notes".to_string(),
            ));
        }

        Ok(cnt as u64)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleCommitment {
    pub issued_root: [u8; 32],
    pub spent_root: [u8; 32],
    pub slot: u64,
}

pub fn compute_merkle_root(serials: &[SerialNumber]) -> [u8; 32] {
    if serials.is_empty() {
        return [0u8; 32];
    }

    let mut sorted: Vec<[u8; 32]> = serials.iter().map(|s| s.0).collect();
    sorted.sort();

    let mut level: Vec<[u8; 32]> = sorted
        .into_iter()
        .map(|bytes| {
            let mut hasher = Sha256::new();
            hasher.update(b"arcmint:merkle:leaf:v1");
            hasher.update(bytes);
            let digest = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            out
        })
        .collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                [0u8; 32]
            };

            let mut hasher = Sha256::new();
            hasher.update(b"arcmint:merkle:node:v1");
            hasher.update(left);
            hasher.update(right);
            let digest = hasher.finalize();
            let mut parent = [0u8; 32];
            parent.copy_from_slice(&digest);
            next.push(parent);

            i += 2;
        }
        level = next;
    }

    level[0]
}

pub fn compute_state_commitment(
    issued: &[SerialNumber],
    spent: &[SerialNumber],
    slot: u64,
) -> MerkleCommitment {
    let issued_root = compute_merkle_root(issued);
    let spent_root = compute_merkle_root(spent);

    MerkleCommitment {
        issued_root,
        spent_root,
        slot,
    }
}

pub fn commitment_hash(c: &MerkleCommitment) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"arcmint:commitment:v1");
    hasher.update(c.issued_root);
    hasher.update(c.spent_root);
    hasher.update(c.slot.to_be_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn current_timestamp() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => dur.as_secs() as i64,
        Err(_) => 0,
    }
}
