use arcmint_core::metrics::{
    render_metrics, GATEWAY_TOKEN_ISSUED_TOTAL, MERCHANT_KEY_VALIDATION_TOTAL,
    RATE_LIMIT_HITS_TOTAL, REGISTRATION_ATTEMPTS_TOTAL, RESOLVE_REQUESTS_TOTAL,
};
use arcmint_core::protocol::{
    IdentityResolutionRequest, IdentityResolutionResponse, RegistrationRequest,
    RegistrationResponse,
};
use arcmint_core::tls::load_tls_server_config;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Json;
use futures::StreamExt;
use hmac::{Hmac, Mac};
use hyper::body::Incoming;
use hyper::Request as HyperRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;
use sha2::Sha256;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Row, SqlitePool};
use std::env;
use std::net::SocketAddr;
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::TcpListenerStream;
use tower::ServiceExt;
use tracing::{error, info, warn};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct GatewayState {
    pool: SqlitePool,
    gateway_secret: String,
    federation_secret: String,
    max_issuance_per_hour: u64,
}

#[derive(serde::Deserialize)]
struct TokenRefreshRequest {
    theta_u: String,
}

#[derive(serde::Deserialize)]
struct RateLimitIncrementRequest {
    theta_u: String,
}

#[derive(serde::Deserialize)]
struct MerchantRegisterRequest {
    name: String,
}

#[derive(serde::Serialize)]
struct MerchantRegisterResponse {
    merchant_id: String,
    api_key: String,
}

#[derive(serde::Serialize)]
struct MerchantInfoResponse {
    merchant_id: String,
    name: String,
    revoked: bool,
}

#[derive(serde::Serialize)]
struct RateLimitStatus {
    theta_u: String,
    issuance_count: i64,
    window_start: i64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tracing_subscriber::fmt().init();

    let port: u16 = env::var("GATEWAY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7002);

    let db_path = env::var("GATEWAY_DB").unwrap_or_else(|_| "gateway.db".to_string());
    let db_url = if db_path.starts_with("sqlite:") {
        db_path.clone()
    } else {
        format!("sqlite://{db_path}")
    };

    let gateway_secret = env::var("GATEWAY_SECRET").expect("GATEWAY_SECRET env var must be set");
    let federation_secret =
        env::var("FEDERATION_SECRET").expect("FEDERATION_SECRET env var must be set");

    let max_issuance_per_hour: u64 = env::var("MAX_ISSUANCE_PER_HOUR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("failed to connect to gateway SQLite DB");

    init_schema(&pool)
        .await
        .expect("failed to initialize gateway DB schema");

    let state = Arc::new(GatewayState {
        pool,
        gateway_secret,
        federation_secret,
        max_issuance_per_hour,
    });

    let merchant_auth_layer = middleware::from_fn_with_state(state.clone(), validate_merchant_key);

    let app = axum::Router::new()
        .route("/register", post(register))
        .route("/resolve", post(resolve))
        .route(
            "/token/refresh",
            post(token_refresh).route_layer(merchant_auth_layer.clone()),
        )
        .route(
            "/rate-limit/increment",
            post(rate_limit_increment).route_layer(merchant_auth_layer.clone()),
        )
        .route(
            "/rate-limit/:theta_u",
            get(rate_limit_get).route_layer(merchant_auth_layer),
        )
        .route("/merchants/register", post(merchant_register))
        .route(
            "/merchants/:merchant_id/rotate-key",
            post(merchant_rotate_key),
        )
        .route(
            "/merchants/:merchant_id",
            get(merchant_get).delete(merchant_delete),
        )
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
            }),
        )
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let acme_domain = env::var("ACME_DOMAIN").ok().filter(|s| !s.is_empty());

    if let Some(domain) = acme_domain {
        let email = env::var("ACME_EMAIL").unwrap_or_default();
        let cache_dir =
            env::var("ACME_CACHE_DIR").unwrap_or_else(|_| "/var/lib/arcmint/acme".to_string());
        let staging = env::var("ACME_STAGING")
            .ok()
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        info!("starting gateway on {addr} with Let's Encrypt TLS for domain {domain}");

        let listener = TcpListener::bind(addr)
            .await
            .expect("failed to bind TCP listener for ACME TLS");
        let tcp_incoming = TcpListenerStream::new(listener);

        let mut acme = AcmeConfig::new([domain]);
        if !email.is_empty() {
            let contact = format!("mailto:{email}");
            acme = acme.contact_push(contact);
        }
        let acme = acme
            .cache(DirCache::new(cache_dir))
            .directory_lets_encrypt(!staging);

        let mut incoming =
            acme.tokio_incoming(tcp_incoming, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);

        while let Some(conn) = incoming.next().await {
            let app = app.clone();
            match conn {
                Ok(stream) => {
                    tokio::spawn(async move {
                        serve_connection(stream, app).await;
                    });
                }
                Err(e) => {
                    error!("ACME TLS error: {e}");
                }
            }
        }
    } else {
        let tls_cert_file =
            env::var("TLS_CERT_FILE").expect("TLS_CERT_FILE env var must be set for gateway TLS");
        let tls_key_file =
            env::var("TLS_KEY_FILE").expect("TLS_KEY_FILE env var must be set for gateway TLS");

        warn!("ACME_DOMAIN not set, starting gateway on {addr} with self-signed TLS certs");

        let tls_config = load_tls_server_config(
            FsPath::new(&tls_cert_file),
            FsPath::new(&tls_key_file),
            None,
        )
        .expect("failed to build gateway TLS server config");
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let listener = TcpListener::bind(addr)
            .await
            .expect("failed to bind TCP listener for TLS");

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

                serve_connection(tls_stream, app).await;
            });
        }
    }
}

async fn serve_connection<S>(stream: S, app: axum::Router)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);

    let tower_service = tower::service_fn(move |req: HyperRequest<Incoming>| {
        let app = app.clone();
        async move { app.clone().oneshot(req).await }
    });

    let service = TowerToHyperService::new(tower_service);

    if let Err(err) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection(io, service)
        .await
    {
        error!("error while serving TLS connection: {err}");
    }
}

async fn init_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS identities (
            theta_u TEXT PRIMARY KEY,
            identity_id TEXT NOT NULL UNIQUE,
            registered_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS rate_limits (
            theta_u TEXT PRIMARY KEY,
            issuance_count INTEGER NOT NULL DEFAULT 0,
            window_start INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS merchants (
            merchant_id TEXT PRIMARY KEY,
            api_key_hash TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            registered_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS merchant_key_rotations (
            merchant_id TEXT PRIMARY KEY,
            old_key_hash TEXT NOT NULL,
            grace_expires_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    Ok(())
}

async fn register(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<RegistrationRequest>,
) -> impl IntoResponse {
    if req.identity_id.trim().is_empty() {
        REGISTRATION_ATTEMPTS_TOTAL
            .with_label_values(&["invalid"])
            .inc();
        return StatusCode::BAD_REQUEST.into_response();
    }

    if req.theta_u.len() != 32 {
        REGISTRATION_ATTEMPTS_TOTAL
            .with_label_values(&["invalid"])
            .inc();
        return StatusCode::BAD_REQUEST.into_response();
    }

    let theta_hex = hex::encode(&req.theta_u);

    let pool = &state.pool;

    let existing = sqlx::query("SELECT 1 FROM identities WHERE identity_id = ?1 LIMIT 1")
        .bind(&req.identity_id)
        .fetch_optional(pool)
        .await;

    let existing = match existing {
        Ok(row) => row,
        Err(e) => {
            error!("register identity lookup error: {e:?}");
            REGISTRATION_ATTEMPTS_TOTAL
                .with_label_values(&["invalid"])
                .inc();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if existing.is_some() {
        REGISTRATION_ATTEMPTS_TOTAL
            .with_label_values(&["duplicate"])
            .inc();
        return StatusCode::CONFLICT.into_response();
    }

    let now = current_timestamp();

    let insert_res = sqlx::query(
        "INSERT INTO identities (theta_u, identity_id, registered_at)
         VALUES (?1, ?2, ?3)",
    )
    .bind(&theta_hex)
    .bind(&req.identity_id)
    .bind(now)
    .execute(pool)
    .await;

    if let Err(e) = insert_res {
        error!("register identity insert error: {e:?}");
        REGISTRATION_ATTEMPTS_TOTAL
            .with_label_values(&["invalid"])
            .inc();
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let init_rate = sqlx::query(
        "INSERT OR IGNORE INTO rate_limits (theta_u, issuance_count, window_start)
         VALUES (?1, 0, ?2)",
    )
    .bind(&theta_hex)
    .bind(now)
    .execute(pool)
    .await;

    if let Err(e) = init_rate {
        error!("register rate_limits init error: {e:?}");
        REGISTRATION_ATTEMPTS_TOTAL
            .with_label_values(&["invalid"])
            .inc();
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let token = compute_gateway_token(&state.gateway_secret);
    let _ = verify_token(&state.gateway_secret, &token);

    let response = RegistrationResponse {
        gateway_token: token,
    };

    REGISTRATION_ATTEMPTS_TOTAL
        .with_label_values(&["success"])
        .inc();

    (StatusCode::OK, Json(response)).into_response()
}

async fn resolve(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    Json(req): Json<IdentityResolutionRequest>,
) -> impl IntoResponse {
    if !authorize(&state.federation_secret, &headers) {
        RESOLVE_REQUESTS_TOTAL
            .with_label_values(&["unauthorized"])
            .inc();
        return StatusCode::UNAUTHORIZED.into_response();
    }

    if req.theta_u.len() != 32 {
        RESOLVE_REQUESTS_TOTAL.with_label_values(&["invalid"]).inc();
        return StatusCode::BAD_REQUEST.into_response();
    }

    let theta_hex = hex::encode(&req.theta_u);

    let row = sqlx::query("SELECT identity_id FROM identities WHERE theta_u = ?1")
        .bind(&theta_hex)
        .fetch_optional(&state.pool)
        .await;

    let row = match row {
        Ok(r) => r,
        Err(e) => {
            error!("resolve DB error: {e:?}");
            RESOLVE_REQUESTS_TOTAL.with_label_values(&["invalid"]).inc();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let Some(row) = row else {
        RESOLVE_REQUESTS_TOTAL
            .with_label_values(&["not_found"])
            .inc();
        return StatusCode::NOT_FOUND.into_response();
    };

    let identity_id: String = match row.try_get("identity_id") {
        Ok(v) => v,
        Err(e) => {
            error!("resolve identity_id column error: {e:?}");
            RESOLVE_REQUESTS_TOTAL.with_label_values(&["invalid"]).inc();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let response = IdentityResolutionResponse { identity_id };

    RESOLVE_REQUESTS_TOTAL.with_label_values(&["found"]).inc();

    (StatusCode::OK, Json(response)).into_response()
}

async fn token_refresh(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<TokenRefreshRequest>,
) -> impl IntoResponse {
    if req.theta_u.len() != 64 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let theta_bytes = match hex::decode(&req.theta_u) {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    if theta_bytes.len() != 32 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let theta_hex = req.theta_u.to_lowercase();

    let exists = sqlx::query("SELECT 1 FROM identities WHERE theta_u = ?1 LIMIT 1")
        .bind(&theta_hex)
        .fetch_optional(&state.pool)
        .await;

    let exists = match exists {
        Ok(r) => r,
        Err(e) => {
            error!("token_refresh DB error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if exists.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let token = compute_gateway_token(&state.gateway_secret);
    let response = RegistrationResponse {
        gateway_token: token,
    };

    GATEWAY_TOKEN_ISSUED_TOTAL.inc();

    (StatusCode::OK, Json(response)).into_response()
}

async fn rate_limit_increment(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    Json(req): Json<RateLimitIncrementRequest>,
) -> impl IntoResponse {
    if !authorize(&state.federation_secret, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    if req.theta_u.len() != 64 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let theta_bytes = match hex::decode(&req.theta_u) {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    if theta_bytes.len() != 32 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let theta_hex = req.theta_u.to_lowercase();
    let now = current_timestamp();

    let row =
        sqlx::query("SELECT issuance_count, window_start FROM rate_limits WHERE theta_u = ?1")
            .bind(&theta_hex)
            .fetch_optional(&state.pool)
            .await;

    let row = match row {
        Ok(r) => r,
        Err(e) => {
            error!("rate_limit_increment select error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let (mut count, mut window_start) = if let Some(row) = row {
        let count: i64 = match row.try_get("issuance_count") {
            Ok(v) => v,
            Err(e) => {
                error!("rate_limit_increment issuance_count column error: {e:?}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let window_start_val: i64 = match row.try_get("window_start") {
            Ok(v) => v,
            Err(e) => {
                error!("rate_limit_increment window_start column error: {e:?}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        (count, window_start_val)
    } else {
        (0, now)
    };

    let window_elapsed = now.saturating_sub(window_start);
    if !(0..3600).contains(&window_elapsed) {
        count = 0;
        window_start = now;
    }

    count = count.saturating_add(1);

    let update_res = sqlx::query(
        "INSERT INTO rate_limits (theta_u, issuance_count, window_start)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(theta_u) DO UPDATE SET
             issuance_count = excluded.issuance_count,
             window_start = excluded.window_start",
    )
    .bind(&theta_hex)
    .bind(count)
    .bind(window_start)
    .execute(&state.pool)
    .await;

    if let Err(e) = update_res {
        error!("rate_limit_increment upsert error: {e:?}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    if (count as u64) > state.max_issuance_per_hour {
        RATE_LIMIT_HITS_TOTAL.inc();
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    StatusCode::OK.into_response()
}

async fn rate_limit_get(
    State(state): State<Arc<GatewayState>>,
    Path(theta_u): Path<String>,
) -> impl IntoResponse {
    if theta_u.len() != 64 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let theta_bytes = match hex::decode(&theta_u) {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    if theta_bytes.len() != 32 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let theta_hex = theta_u.to_lowercase();

    let row =
        sqlx::query("SELECT issuance_count, window_start FROM rate_limits WHERE theta_u = ?1")
            .bind(&theta_hex)
            .fetch_optional(&state.pool)
            .await;

    let row = match row {
        Ok(r) => r,
        Err(e) => {
            error!("rate_limit_get select error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let Some(row) = row else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let issuance_count: i64 = match row.try_get("issuance_count") {
        Ok(v) => v,
        Err(e) => {
            error!("rate_limit_get issuance_count column error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let window_start: i64 = match row.try_get("window_start") {
        Ok(v) => v,
        Err(e) => {
            error!("rate_limit_get window_start column error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let status = RateLimitStatus {
        theta_u: theta_hex,
        issuance_count,
        window_start,
    };

    (StatusCode::OK, Json(status)).into_response()
}

async fn health() -> impl IntoResponse {
    StatusCode::OK
}

async fn merchant_register(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    Json(req): Json<MerchantRegisterRequest>,
) -> impl IntoResponse {
    if !authorize_operator(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let name = req.name.trim();
    if name.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let merchant_id = uuid::Uuid::new_v4().to_string();
    let api_key_bytes: [u8; 32] = rand::random();
    let api_key = hex::encode(api_key_bytes);
    let api_key_hash = compute_api_key_hash(&api_key);
    let now = current_timestamp();

    let insert_res = sqlx::query(
        "INSERT INTO merchants (merchant_id, api_key_hash, name, registered_at, revoked)
         VALUES (?1, ?2, ?3, ?4, 0)",
    )
    .bind(&merchant_id)
    .bind(&api_key_hash)
    .bind(name)
    .bind(now)
    .execute(&state.pool)
    .await;

    if let Err(e) = insert_res {
        error!("merchant_register insert error: {e:?}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let resp = MerchantRegisterResponse {
        merchant_id,
        api_key,
    };

    (StatusCode::OK, Json(resp)).into_response()
}

async fn merchant_rotate_key(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    Path(merchant_id): Path<String>,
) -> impl IntoResponse {
    if !authorize_operator(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let current = sqlx::query("SELECT api_key_hash FROM merchants WHERE merchant_id = ?1")
        .bind(&merchant_id)
        .fetch_optional(&state.pool)
        .await;

    let row = match current {
        Ok(r) => r,
        Err(e) => {
            error!("merchant_rotate_key select error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let Some(row) = row else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let old_hash: String = match row.try_get("api_key_hash") {
        Ok(v) => v,
        Err(e) => {
            error!("merchant_rotate_key api_key_hash column error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let api_key_bytes: [u8; 32] = rand::random();
    let api_key = hex::encode(api_key_bytes);
    let new_hash = compute_api_key_hash(&api_key);

    let now = current_timestamp();
    let grace_expires_at = now.saturating_add(86400);

    let mut tx = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            error!("merchant_rotate_key begin tx error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let upsert_rotation = sqlx::query(
        "INSERT INTO merchant_key_rotations (merchant_id, old_key_hash, grace_expires_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(merchant_id) DO UPDATE SET
             old_key_hash = excluded.old_key_hash,
             grace_expires_at = excluded.grace_expires_at",
    )
    .bind(&merchant_id)
    .bind(&old_hash)
    .bind(grace_expires_at)
    .execute(&mut *tx)
    .await;

    if let Err(e) = upsert_rotation {
        error!("merchant_rotate_key rotation upsert error: {e:?}");
        if let Err(e2) = tx.rollback().await {
            error!("merchant_rotate_key rollback error: {e2:?}");
        }
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let update_merchant =
        sqlx::query("UPDATE merchants SET api_key_hash = ?1 WHERE merchant_id = ?2")
            .bind(&new_hash)
            .bind(&merchant_id)
            .execute(&mut *tx)
            .await;

    if let Err(e) = update_merchant {
        error!("merchant_rotate_key update merchant error: {e:?}");
        if let Err(e2) = tx.rollback().await {
            error!("merchant_rotate_key rollback error: {e2:?}");
        }
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    if let Err(e) = tx.commit().await {
        error!("merchant_rotate_key commit error: {e:?}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let resp = MerchantRegisterResponse {
        merchant_id,
        api_key,
    };

    (StatusCode::OK, Json(resp)).into_response()
}

async fn merchant_get(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    Path(merchant_id): Path<String>,
) -> impl IntoResponse {
    if !authorize_operator(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let row = sqlx::query("SELECT name, revoked FROM merchants WHERE merchant_id = ?1")
        .bind(&merchant_id)
        .fetch_optional(&state.pool)
        .await;

    let row = match row {
        Ok(r) => r,
        Err(e) => {
            error!("merchant_get select error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let Some(row) = row else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let name: String = match row.try_get("name") {
        Ok(v) => v,
        Err(e) => {
            error!("merchant_get name column error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let revoked_val: i64 = match row.try_get("revoked") {
        Ok(v) => v,
        Err(e) => {
            error!("merchant_get revoked column error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let resp = MerchantInfoResponse {
        merchant_id,
        name,
        revoked: revoked_val != 0,
    };

    (StatusCode::OK, Json(resp)).into_response()
}

async fn merchant_delete(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    Path(merchant_id): Path<String>,
) -> impl IntoResponse {
    if !authorize_operator(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let res = sqlx::query("UPDATE merchants SET revoked = 1 WHERE merchant_id = ?1")
        .bind(&merchant_id)
        .execute(&state.pool)
        .await;

    match res {
        Ok(result) => {
            if result.rows_affected() == 0 {
                StatusCode::NOT_FOUND.into_response()
            } else {
                StatusCode::NO_CONTENT.into_response()
            }
        }
        Err(e) => {
            error!("merchant_delete update error: {e:?}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn validate_merchant_key(
    State(state): State<Arc<GatewayState>>,
    req: Request,
    next: middleware::Next,
) -> impl IntoResponse {
    let header_val = req
        .headers()
        .get("X-Merchant-Key")
        .and_then(|v| v.to_str().ok());

    let Some(api_key) = header_val else {
        MERCHANT_KEY_VALIDATION_TOTAL
            .with_label_values(&["invalid"])
            .inc();
        return StatusCode::UNAUTHORIZED.into_response();
    };

    if api_key.len() != 64 {
        MERCHANT_KEY_VALIDATION_TOTAL
            .with_label_values(&["invalid"])
            .inc();
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let hash_hex = compute_api_key_hash(api_key);
    let now = current_timestamp();

    let current =
        sqlx::query("SELECT api_key_hash, revoked FROM merchants WHERE api_key_hash = ?1")
            .bind(&hash_hex)
            .fetch_optional(&state.pool)
            .await;

    let mut authorized = false;

    match current {
        Ok(Some(row)) => {
            let stored_hash: String = match row.try_get("api_key_hash") {
                Ok(v) => v,
                Err(e) => {
                    error!("validate_merchant_key api_key_hash column error: {e:?}");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            let revoked: i64 = match row.try_get("revoked") {
                Ok(v) => v,
                Err(e) => {
                    error!("validate_merchant_key revoked column error: {e:?}");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };

            if revoked == 0 && constant_time_eq_hex(&hash_hex, &stored_hash) {
                authorized = true;
            } else if revoked != 0 && constant_time_eq_hex(&hash_hex, &stored_hash) {
                MERCHANT_KEY_VALIDATION_TOTAL
                    .with_label_values(&["revoked"])
                    .inc();
                return StatusCode::UNAUTHORIZED.into_response();
            }
        }
        Ok(None) => {}
        Err(e) => {
            error!("validate_merchant_key merchants query error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    if !authorized {
        let rotation = sqlx::query(
            "SELECT old_key_hash, grace_expires_at FROM merchant_key_rotations WHERE old_key_hash = ?1",
        )
        .bind(&hash_hex)
        .fetch_optional(&state.pool)
        .await;

        match rotation {
            Ok(Some(row)) => {
                let old_hash: String = match row.try_get("old_key_hash") {
                    Ok(v) => v,
                    Err(e) => {
                        error!("validate_merchant_key old_key_hash column error: {e:?}");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };
                let grace_expires_at: i64 = match row.try_get("grace_expires_at") {
                    Ok(v) => v,
                    Err(e) => {
                        error!("validate_merchant_key grace_expires_at column error: {e:?}");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };

                if grace_expires_at > now && constant_time_eq_hex(&hash_hex, &old_hash) {
                    authorized = true;
                }
            }
            Ok(None) => {}
            Err(e) => {
                error!("validate_merchant_key rotations query error: {e:?}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }

    if !authorized {
        MERCHANT_KEY_VALIDATION_TOTAL
            .with_label_values(&["invalid"])
            .inc();
        return StatusCode::UNAUTHORIZED.into_response();
    }

    MERCHANT_KEY_VALIDATION_TOTAL
        .with_label_values(&["valid"])
        .inc();

    next.run(req).await
}

fn compute_gateway_token(secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(b"arcmint-gateway-token");
    let bytes = mac.finalize().into_bytes();
    hex::encode(bytes)
}

fn verify_token(secret: &str, token: &str) -> bool {
    let provided = match hex::decode(token) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(b"arcmint-gateway-token");
    mac.verify_slice(&provided).is_ok()
}

fn authorize(secret: &str, headers: &HeaderMap) -> bool {
    if let Some(value) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = value.to_str() {
            let prefix = "Bearer ";
            if let Some(token) = s.strip_prefix(prefix) {
                return token == secret;
            }
        }
    }
    false
}

fn authorize_operator(headers: &HeaderMap) -> bool {
    if let Some(value) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = value.to_str() {
            let prefix = "Bearer ";
            if let Some(token) = s.strip_prefix(prefix) {
                if let Ok(expected) = env::var("OPERATOR_SECRET") {
                    return token == expected;
                }
            }
        }
    }
    false
}

fn compute_api_key_hash(api_key: &str) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let a_bytes = match hex::decode(a) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let b_bytes = match hex::decode(b) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    a_bytes.ct_eq(&b_bytes).unwrap_u8() == 1
}

fn current_timestamp() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => dur.as_secs() as i64,
        Err(_) => 0,
    }
}
