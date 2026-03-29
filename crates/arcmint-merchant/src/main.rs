use arcmint_core::crypto::{generators, SerialNumber};
use arcmint_core::frost_ops::load_public_key_package;
use arcmint_core::metrics::{
    render_metrics, ACCEPTED_PAYMENTS_TOTAL, EXPIRED_PENDING_SPENDS_TOTAL,
    NOTE_VERIFICATION_FAILURES_TOTAL, PAYMENT_INITIATION_TOTAL, PENDING_SPEND_COUNT,
};
use arcmint_core::note::SignedNote;
use arcmint_core::protocol::{SpendChallenge, SpendProof, SpendRequest, SpendResponse, CURRENT_PROTOCOL_VERSION};
use arcmint_core::spending::{verify_frost_signature, verify_spend_proof};
use axum::extract::{Query, Request, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Json;
use frost_ristretto255::keys::PublicKeyPackage;
use rand::rngs::{OsRng, ThreadRng};
use rand::{thread_rng, Rng, RngCore};
use reqwest::Client;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Row, SqlitePool};
use std::env;
use std::net::SocketAddr;
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tracing::{error, info};

#[derive(Clone)]
struct MerchantState {
    pool: SqlitePool,
    coordinator_url: String,
    public_key_package: PublicKeyPackage,
    http_client: Client,
    operator_secrets: Vec<String>,
}

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<MerchantState>>,
}

#[derive(serde::Deserialize)]
struct PaymentsQuery {
    page: Option<u64>,
    limit: Option<u64>,
}

#[derive(serde::Serialize)]
struct PaymentRow {
    serial: String,
    denomination: u64,
    accepted_at: i64,
}

#[derive(serde::Deserialize)]
struct PaymentCompleteRequest {
    protocol_version: u8,
    merchant_nonce: [u8; 32],
    serial: SerialNumber,
    proof: SpendProof,
}

#[derive(serde::Serialize)]
struct CoordinatorSpendVerifyRequest {
    serial: SerialNumber,
    proof: SpendProof,
    challenge_bits: Option<Vec<u8>>,
    note: Option<SignedNote>,
    merchant_nonce: Option<[u8; 32]>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt().init();

    let port: u16 = env::var("MERCHANT_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7003);

    let db_path = env::var("MERCHANT_DB").unwrap_or_else(|_| "merchant.db".to_string());
    let db_url = if db_path.starts_with("sqlite:") {
        db_path
    } else {
        format!("sqlite://{db_path}")
    };

    let coordinator_url = env::var("COORDINATOR_URL").expect("COORDINATOR_URL env var must be set");
    let operator_secrets: Vec<String> = env::var("OPERATOR_SECRET")
        .expect("OPERATOR_SECRET env var must be set")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if operator_secrets.is_empty() {
        panic!("OPERATOR_SECRET must contain at least one secret");
    }
    for (i, s) in operator_secrets.iter().enumerate() {
        validate_secret(&format!("OPERATOR_SECRET[{i}]"), s);
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("failed to connect to SQLite");

    init_schema(&pool).await.expect("failed to init schema");

    let pubkey_path = env::var("FROST_PUBKEY_FILE").expect("FROST_PUBKEY_FILE env var must be set");
    let public_key_package = load_public_key_package(FsPath::new(&pubkey_path))
        .expect("failed to load public key package from file");

    let http_client = Client::new();

    let state = MerchantState {
        pool: pool.clone(),
        coordinator_url,
        public_key_package,
        http_client,
        operator_secrets,
    };

    let shared = AppState {
        inner: Arc::new(Mutex::new(state)),
    };

    let cleanup_pool = pool.clone();
    tokio::spawn(async move {
        cleanup_loop(cleanup_pool).await;
    });

    let operator_auth_layer =
        middleware::from_fn_with_state(shared.clone(), require_operator_auth);

    let app = axum::Router::new()
        .route("/payment/initiate", post(payment_initiate))
        .route("/payment/complete", post(payment_complete))
        .route("/payments", get(payments_list))
        .route("/health", get(health))
        .route(
            "/metrics",
            get(|| async {
                let body = render_metrics();
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4",
                    )],
                    body,
                )
            })
            .route_layer(operator_auth_layer),
        )
        .with_state(shared);

    let bind_host = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
    let addr: SocketAddr = format!("{bind_host}:{port}")
        .parse()
        .expect("invalid BIND_ADDR");

    let tls_cert_file =
        env::var("TLS_CERT_FILE").expect("TLS_CERT_FILE env var must be set for merchant TLS");
    let tls_key_file =
        env::var("TLS_KEY_FILE").expect("TLS_KEY_FILE env var must be set for merchant TLS");

    use arcmint_core::tls::load_tls_server_config;
    use hyper::body::Incoming;
    use hyper::Request as HyperRequest;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::service::TowerToHyperService;
    use tokio_rustls::TlsAcceptor;
    use tower::ServiceExt;

    info!("starting merchant on {addr} (TLS enabled)");

    let tls_config =
        load_tls_server_config(FsPath::new(&tls_cert_file), FsPath::new(&tls_key_file), None)
            .expect("failed to build merchant TLS server config");
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .expect("failed to accept connection");
        let tls_acceptor = tls_acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    error!("TLS handshake error from {peer_addr}: {e}");
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);

            let tower_service = tower::service_fn(move |req: HyperRequest<Incoming>| {
                let app = app.clone();
                async move { app.clone().oneshot(req).await }
            });

            let service = TowerToHyperService::new(tower_service);

            if let Err(err) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
            {
                error!("error while serving TLS connection from {peer_addr}: {err}");
            }
        });
    }
}

async fn require_operator_auth(
    State(state): State<AppState>,
    req: Request,
    next: middleware::Next,
) -> impl IntoResponse {
    let secrets = {
        let guard = state.inner.lock().await;
        guard.operator_secrets.clone()
    };
    let header_val = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if let Some(h) = header_val {
        if let Some(token) = h.strip_prefix("Bearer ") {
            let token_bytes = token.as_bytes();
            // Check all secrets; iterate all to avoid timing leaks on list position.
            let mut authorized = false;
            for secret in &secrets {
                let expected = secret.as_bytes();
                if token_bytes.len() == expected.len()
                    && token_bytes.ct_eq(expected).unwrap_u8() == 1
                {
                    authorized = true;
                }
            }
            if authorized {
                return next.run(req).await;
            }
        }
    }
    StatusCode::UNAUTHORIZED.into_response()
}

fn validate_secret(name: &str, value: &str) {
    if value.len() < 32 {
        panic!("{name} must be at least 32 characters long");
    }
    if value.starts_with("dev-") {
        panic!("{name} must not use a development placeholder (starts with 'dev-')");
    }
}

async fn init_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS accepted_payments (
             serial TEXT PRIMARY KEY,
             denomination INTEGER NOT NULL,
             accepted_at INTEGER NOT NULL
         )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pending_spends (
             serial TEXT PRIMARY KEY,
             challenge_bits TEXT NOT NULL,
             merchant_nonce TEXT NOT NULL,
             note_json TEXT NOT NULL,
             expires_at INTEGER NOT NULL
         )",
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[axum::debug_handler]
async fn payment_initiate(
    State(state): State<AppState>,
    Json(req): Json<SpendRequest>,
) -> impl IntoResponse {
    if req.protocol_version != CURRENT_PROTOCOL_VERSION {
        PAYMENT_INITIATION_TOTAL
            .with_label_values(&["rejected"])
            .inc();
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "unsupported_protocol_version",
                "supported": CURRENT_PROTOCOL_VERSION,
                "received": req.protocol_version,
            })),
        )
            .into_response();
    }

    let signed = req.note;
    let data = signed.data.clone();

    PAYMENT_INITIATION_TOTAL
        .with_label_values(&["started"])
        .inc();

    let (public_key_package, coordinator_url, client, pool) = {
        let guard = state.inner.lock().await;
        (
            guard.public_key_package.clone(),
            guard.coordinator_url.clone(),
            guard.http_client.clone(),
            guard.pool.clone(),
        )
    };

    if let Err(e) = verify_frost_signature(&data, &signed.signature, &public_key_package) {
        error!("FROST signature verification failed: {e:?}");
        NOTE_VERIFICATION_FAILURES_TOTAL
            .with_label_values(&["invalid_signature"])
            .inc();
        let response = SpendResponse { protocol_version: CURRENT_PROTOCOL_VERSION,
            accepted: false,
            reason: Some("invalid signature".to_string()),
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    if data.expires_at > 0 && current_timestamp() > data.expires_at {
        NOTE_VERIFICATION_FAILURES_TOTAL
            .with_label_values(&["expired"])
            .inc();
        let response = SpendResponse { protocol_version: CURRENT_PROTOCOL_VERSION,
            accepted: false,
            reason: Some("note expired".to_string()),
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    let serial_hex = hex::encode(data.serial.0);

    let exists = sqlx::query("SELECT 1 FROM accepted_payments WHERE serial = ?1 LIMIT 1")
        .bind(&serial_hex)
        .fetch_optional(&pool)
        .await;

    match exists {
        Ok(Some(_)) => {
            PAYMENT_INITIATION_TOTAL
                .with_label_values(&["duplicate"])
                .inc();
            let response = SpendResponse { protocol_version: CURRENT_PROTOCOL_VERSION,
                accepted: false,
                reason: Some("note already accepted".to_string()),
            };
            return (StatusCode::OK, Json(response)).into_response();
        }
        Ok(None) => {}
        Err(e) => {
            error!("accepted_payments lookup error: {e:?}");
            PAYMENT_INITIATION_TOTAL.with_label_values(&["error"]).inc();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    let url = format!("{coordinator_url}/registry/issued/{serial_hex}");
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            error!("coordinator registry issued request error: {e}");
            PAYMENT_INITIATION_TOTAL.with_label_values(&["error"]).inc();
            let response = SpendResponse { protocol_version: CURRENT_PROTOCOL_VERSION,
                accepted: false,
                reason: Some("upstream coordinator error".to_string()),
            };
            return (StatusCode::OK, Json(response)).into_response();
        }
    };

    match resp.status() {
        s if s.is_success() => {}
        StatusCode::NOT_FOUND => {
            PAYMENT_INITIATION_TOTAL
                .with_label_values(&["rejected"])
                .inc();
            let response = SpendResponse { protocol_version: CURRENT_PROTOCOL_VERSION,
                accepted: false,
                reason: Some("note not issued".to_string()),
            };
            return (StatusCode::OK, Json(response)).into_response();
        }
        other => {
            error!("coordinator registry issued HTTP {other}");
            PAYMENT_INITIATION_TOTAL.with_label_values(&["error"]).inc();
            let response = SpendResponse { protocol_version: CURRENT_PROTOCOL_VERSION,
                accepted: false,
                reason: Some("upstream coordinator error".to_string()),
            };
            return (StatusCode::OK, Json(response)).into_response();
        }
    }

    let k = data.pairs.len();
    let challenge_bits = {
        let mut rng: ThreadRng = thread_rng();
        let mut bits = Vec::with_capacity(k);
        for _ in 0..k {
            let bit: u8 = rng.gen_range(0..=1);
            bits.push(bit);
        }
        bits
    };

    let challenge_hex = hex::encode(&challenge_bits);

    let mut merchant_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut merchant_nonce);
    let nonce_hex = hex::encode(merchant_nonce);

    let note_json = match serde_json::to_string(&signed) {
        Ok(s) => s,
        Err(e) => {
            error!("note serialization error: {e}");
            PAYMENT_INITIATION_TOTAL.with_label_values(&["error"]).inc();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let now = current_timestamp();
    let expires_at = now.saturating_add(300);

    let insert_res = sqlx::query(
        "INSERT OR REPLACE INTO pending_spends (serial, challenge_bits, merchant_nonce, note_json, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(&serial_hex)
    .bind(&challenge_hex)
    .bind(&nonce_hex)
    .bind(&note_json)
    .bind(expires_at)
    .execute(&pool)
    .await;

    if let Err(e) = insert_res {
        error!("pending_spends upsert error: {e:?}");
        PAYMENT_INITIATION_TOTAL.with_label_values(&["error"]).inc();
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let count_res = sqlx::query("SELECT COUNT(*) as cnt FROM pending_spends")
        .fetch_one(&pool)
        .await;
    if let Ok(row) = count_res {
        if let Ok(cnt) = row.try_get::<i64, _>("cnt") {
            PENDING_SPEND_COUNT.set(cnt as f64);
        }
    }

    let response = SpendChallenge {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        merchant_nonce,
        challenge_bits,
    };

    PAYMENT_INITIATION_TOTAL
        .with_label_values(&["success"])
        .inc();

    (StatusCode::OK, Json(response)).into_response()
}

#[axum::debug_handler]
async fn payment_complete(
    State(state): State<AppState>,
    Json(req): Json<PaymentCompleteRequest>,
) -> impl IntoResponse {
    if req.protocol_version != CURRENT_PROTOCOL_VERSION {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "unsupported_protocol_version",
                "supported": CURRENT_PROTOCOL_VERSION,
                "received": req.protocol_version,
            })),
        )
            .into_response();
    }

    if req.serial != req.proof.serial {
        NOTE_VERIFICATION_FAILURES_TOTAL
            .with_label_values(&["serial_mismatch"])
            .inc();
        let response = SpendResponse { protocol_version: CURRENT_PROTOCOL_VERSION,
            accepted: false,
            reason: Some("serial mismatch".to_string()),
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    let (coordinator_url, client, pool) = {
        let guard = state.inner.lock().await;
        (
            guard.coordinator_url.clone(),
            guard.http_client.clone(),
            guard.pool.clone(),
        )
    };

    let serial_hex = hex::encode(req.serial.0);

    let row = sqlx::query(
        "SELECT challenge_bits, note_json, expires_at FROM pending_spends WHERE serial = ?1",
    )
    .bind(&serial_hex)
    .fetch_optional(&pool)
    .await;

    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            NOTE_VERIFICATION_FAILURES_TOTAL
                .with_label_values(&["no_pending_spend"])
                .inc();
            let response = SpendResponse { protocol_version: CURRENT_PROTOCOL_VERSION,
                accepted: false,
                reason: Some("no pending spend".to_string()),
            };
            return (StatusCode::OK, Json(response)).into_response();
        }
        Err(e) => {
            error!("pending_spends select error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let challenge_hex: String = match row.try_get("challenge_bits") {
        Ok(v) => v,
        Err(e) => {
            error!("challenge_bits column error: {e:?}");
            NOTE_VERIFICATION_FAILURES_TOTAL
                .with_label_values(&["db_error"])
                .inc();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let stored_nonce_hex: String = match row.try_get("merchant_nonce") {
        Ok(v) => v,
        Err(e) => {
            error!("merchant_nonce column error: {e:?}");
            NOTE_VERIFICATION_FAILURES_TOTAL
                .with_label_values(&["db_error"])
                .inc();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let stored_nonce = match hex::decode(&stored_nonce_hex) {
        Ok(v) if v.len() == 32 => v,
        _ => {
            error!("merchant_nonce decode error");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if req.merchant_nonce.ct_eq(stored_nonce.as_slice()).unwrap_u8() == 0 {
        NOTE_VERIFICATION_FAILURES_TOTAL
            .with_label_values(&["nonce_mismatch"])
            .inc();
        let response = SpendResponse { protocol_version: CURRENT_PROTOCOL_VERSION,
            accepted: false,
            reason: Some("invalid merchant nonce".to_string()),
        };
        return (StatusCode::OK, Json(response)).into_response();
    }
    let note_json: String = match row.try_get("note_json") {
        Ok(v) => v,
        Err(e) => {
            error!("note_json column error: {e:?}");
            NOTE_VERIFICATION_FAILURES_TOTAL
                .with_label_values(&["db_error"])
                .inc();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let expires_at: i64 = match row.try_get("expires_at") {
        Ok(v) => v,
        Err(e) => {
            error!("expires_at column error: {e:?}");
            NOTE_VERIFICATION_FAILURES_TOTAL
                .with_label_values(&["db_error"])
                .inc();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let now = current_timestamp();
    if now > expires_at {
        let delete_res = sqlx::query("DELETE FROM pending_spends WHERE serial = ?1")
            .bind(&serial_hex)
            .execute(&pool)
            .await;

        if let Ok(done) = delete_res {
            let affected = done.rows_affected();
            if affected > 0 {
                EXPIRED_PENDING_SPENDS_TOTAL.inc_by(affected as f64);
            }
        }

        let response = SpendResponse { protocol_version: CURRENT_PROTOCOL_VERSION,
            accepted: false,
            reason: Some("challenge expired".to_string()),
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    let challenge_bytes = match hex::decode(&challenge_hex) {
        Ok(v) => v,
        Err(e) => {
            error!("challenge_bits decode error: {e}");
            NOTE_VERIFICATION_FAILURES_TOTAL
                .with_label_values(&["decode_error"])
                .inc();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let signed: SignedNote = match serde_json::from_str(&note_json) {
        Ok(n) => n,
        Err(e) => {
            error!("note_json parse error: {e}");
            NOTE_VERIFICATION_FAILURES_TOTAL
                .with_label_values(&["decode_error"])
                .inc();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let data = signed.data.clone();
    let (g, h) = generators();

    if let Err(e) = verify_spend_proof(&data, &req.proof, &challenge_bytes, &g, &h) {
        error!("spend proof verification failed: {e:?}");
        NOTE_VERIFICATION_FAILURES_TOTAL
            .with_label_values(&["invalid_spend_proof"])
            .inc();
        let response = SpendResponse { protocol_version: CURRENT_PROTOCOL_VERSION,
            accepted: false,
            reason: Some("invalid spend proof".to_string()),
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    let verify_req = CoordinatorSpendVerifyRequest {
        serial: data.serial,
        proof: req.proof.clone(),
        challenge_bits: Some(challenge_bytes),
        note: Some(signed.clone()),
        merchant_nonce: None,
    };

    // info!("sending coordinator spend verify request: {:?}", verify_req);

    let url = format!("{coordinator_url}/spend/verify");
    let resp = match client.post(&url).json(&verify_req).send().await {
        Ok(r) => r,
        Err(e) => {
            error!("coordinator spend verify request error: {e}");
            let response = SpendResponse { protocol_version: CURRENT_PROTOCOL_VERSION,
                accepted: false,
                reason: Some("upstream coordinator error".to_string()),
            };
            return (StatusCode::OK, Json(response)).into_response();
        }
    };

    if !resp.status().is_success() {
        error!("coordinator spend verify HTTP {}", resp.status());
        let response = SpendResponse { protocol_version: CURRENT_PROTOCOL_VERSION,
            accepted: false,
            reason: Some("upstream coordinator error".to_string()),
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    let spend_response: SpendResponse = match resp.json().await {
        Ok(r) => r,
        Err(e) => {
            error!("coordinator spend verify JSON error: {e}");
            NOTE_VERIFICATION_FAILURES_TOTAL
                .with_label_values(&["decode_error"])
                .inc();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if spend_response.accepted {
        let now_ts = current_timestamp();
        let insert_res = sqlx::query(
            "INSERT OR IGNORE INTO accepted_payments (serial, denomination, accepted_at)
             VALUES (?1, ?2, ?3)",
        )
        .bind(&serial_hex)
        .bind(data.denomination as i64)
        .bind(now_ts)
        .execute(&pool)
        .await;

        if let Err(e) = insert_res {
            error!("accepted_payments insert error: {e:?}");
            NOTE_VERIFICATION_FAILURES_TOTAL
                .with_label_values(&["db_error"])
                .inc();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }

        let delete_res = sqlx::query("DELETE FROM pending_spends WHERE serial = ?1")
            .bind(&serial_hex)
            .execute(&pool)
            .await;

        if let Err(e) = delete_res {
            error!("pending_spends delete error after accept: {e:?}");
        }

        ACCEPTED_PAYMENTS_TOTAL.inc();

        let count_res = sqlx::query("SELECT COUNT(*) as cnt FROM pending_spends")
            .fetch_one(&pool)
            .await;
        if let Ok(row) = count_res {
            if let Ok(cnt) = row.try_get::<i64, _>("cnt") {
                PENDING_SPEND_COUNT.set(cnt as f64);
            }
        }
    }

    (StatusCode::OK, Json(spend_response)).into_response()
}

#[axum::debug_handler]
async fn payments_list(
    State(state): State<AppState>,
    Query(query): Query<PaymentsQuery>,
) -> impl IntoResponse {
    let pool = {
        let guard = state.inner.lock().await;
        guard.pool.clone()
    };

    let page = query.page.unwrap_or(0);
    let limit = query.limit.unwrap_or(20).min(100);
    let offset = page.saturating_mul(limit);

    let rows = sqlx::query(
        "SELECT serial, denomination, accepted_at
         FROM accepted_payments
         ORDER BY accepted_at DESC
         LIMIT ?1 OFFSET ?2",
    )
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(&pool)
    .await;

    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            error!("payments select error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let serial: String = match row.try_get("serial") {
            Ok(v) => v,
            Err(e) => {
                error!("payments serial column error: {e:?}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let denomination: i64 = match row.try_get("denomination") {
            Ok(v) => v,
            Err(e) => {
                error!("payments denomination column error: {e:?}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let accepted_at: i64 = match row.try_get("accepted_at") {
            Ok(v) => v,
            Err(e) => {
                error!("payments accepted_at column error: {e:?}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        out.push(PaymentRow {
            serial,
            denomination: denomination.max(0) as u64,
            accepted_at,
        });
    }

    (StatusCode::OK, Json(out)).into_response()
}

async fn cleanup_loop(pool: SqlitePool) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let now = current_timestamp();
        let res = sqlx::query("DELETE FROM pending_spends WHERE expires_at < ?1")
            .bind(now)
            .execute(&pool)
            .await;

        match res {
            Ok(done) => {
                let affected = done.rows_affected();
                if affected > 0 {
                    EXPIRED_PENDING_SPENDS_TOTAL.inc_by(affected as f64);
                }
            }
            Err(e) => {
                error!("pending_spends cleanup error: {e:?}");
            }
        }

        let count_res = sqlx::query("SELECT COUNT(*) as cnt FROM pending_spends")
            .fetch_one(&pool)
            .await;
        if let Ok(row) = count_res {
            if let Ok(cnt) = row.try_get::<i64, _>("cnt") {
                PENDING_SPEND_COUNT.set(cnt as f64);
            }
        }
    }
}

async fn health() -> impl IntoResponse {
    StatusCode::OK
}

fn current_timestamp() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    now.as_secs() as i64
}
