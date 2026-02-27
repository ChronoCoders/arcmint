use arcmint_core::crypto::SerialNumber;
use arcmint_core::frost_ops::{load_key_package, SignerIdentifier, SigningCommitment};
use arcmint_core::metrics::{
    render_metrics, ACTIVE_NONCES_COUNT, DB_WRITE_LATENCY_SECONDS, DOUBLE_SPEND_ATTEMPTS_TOTAL,
    FROST_ROUND_DURATION_SECONDS,
};
use arcmint_core::protocol::AuditResponse;
use arcmint_core::registry::{compute_state_commitment, IssuedRegistry, SpentRegistry};
use arcmint_core::tls::load_tls_server_config;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Json;
use frost_ristretto255::keys::KeyPackage;
use hyper::body::Incoming;
use hyper::Request as HyperRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use sqlx::sqlite::SqlitePoolOptions;
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, error, info};

use frost_ristretto255::round1::SigningNonces;

#[derive(Clone)]
struct SignerState {
    key_package: KeyPackage,
    active_nonces: HashMap<String, (SigningNonces, Instant)>,
    issued: IssuedRegistry,
    spent: SpentRegistry,
}

#[derive(Clone)]
struct AppState {
    signer: Arc<Mutex<SignerState>>,
    coordinator_cn: String,
}

#[derive(serde::Deserialize)]
struct Round1CommitRequest {
    session_id: String,
}

#[derive(serde::Deserialize)]
struct Round2SignRequest {
    session_id: String,
    message: Vec<u8>,
    all_commitments: Vec<(SignerIdentifier, SigningCommitment)>,
}

#[derive(serde::Deserialize)]
struct IssueRequest {
    serial: SerialNumber,
    denomination: u64,
}

#[derive(serde::Deserialize)]
struct SpendRegistryRequest {
    serial: SerialNumber,
    challenge: Vec<u8>,
    second_challenge: Option<Vec<u8>>,
    theta_u: Option<Vec<u8>>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tracing_subscriber::fmt().init();

    let port: u16 = env::var("FEDERATION_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7001);

    let db_path = env::var("FEDERATION_DB").unwrap_or_else(|_| "federation.db".to_string());
    let db_url = if db_path.starts_with("sqlite:") {
        db_path
    } else {
        format!("sqlite://{}", db_path)
    };

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("failed to connect to SQLite");

    let issued = IssuedRegistry::new(pool.clone());
    let spent = SpentRegistry::new(pool.clone());

    issued
        .init_schema()
        .await
        .expect("failed to init issued registry schema");
    spent
        .init_schema()
        .await
        .expect("failed to init spent registry schema");

    let key_path = env::var("FROST_KEY_FILE").unwrap_or_else(|_| "frost_key.json".to_string());
    let key_file_exists = FsPath::new(&key_path).exists();
    if !key_file_exists {
        panic!("FROST key package file {key_path} does not exist");
    }

    let key_package =
        load_key_package(FsPath::new(&key_path)).expect("failed to load key package from file");

    let signer_id_env = env::var("SIGNER_ID").expect("SIGNER_ID env var must be set");
    let _signer_id_value: u16 = signer_id_env
        .parse()
        .expect("SIGNER_ID must be a valid u16");

    let tls_cert_file =
        env::var("TLS_CERT_FILE").expect("TLS_CERT_FILE env var must be set for signer TLS");
    let tls_key_file =
        env::var("TLS_KEY_FILE").expect("TLS_KEY_FILE env var must be set for signer TLS");
    let tls_ca_file =
        env::var("TLS_CA_FILE").expect("TLS_CA_FILE env var must be set for signer mTLS");

    let coordinator_cn =
        env::var("COORDINATOR_CN").unwrap_or_else(|_| "arcmint-coordinator".to_string());

    let signer_state = SignerState {
        key_package,
        active_nonces: HashMap::new(),
        issued,
        spent,
    };

    let signer_arc = Arc::new(Mutex::new(signer_state));

    let nonce_ttl_secs: u64 = env::var("SESSION_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);

    let cleanup_state = signer_arc.clone();
    tokio::spawn(run_nonce_cleanup(cleanup_state, nonce_ttl_secs));

    let app_state = AppState {
        signer: signer_arc,
        coordinator_cn,
    };

    let auth_layer = middleware::from_fn_with_state(app_state.clone(), require_coordinator_cn);

    let app = axum::Router::new()
        .route(
            "/round1/commit",
            post(round1_commit).route_layer(auth_layer.clone()),
        )
        .route(
            "/round2/sign",
            post(round2_sign).route_layer(auth_layer.clone()),
        )
        .route(
            "/registry/issue",
            post(registry_issue).route_layer(auth_layer.clone()),
        )
        .route(
            "/registry/spend",
            post(registry_spend).route_layer(auth_layer),
        )
        .route("/registry/issued/:serial", get(registry_issued_get))
        .route("/registry/spent/:serial", get(registry_spent_get))
        .route("/audit", get(audit))
        .route("/metrics", get(metrics))
        .route("/health", get(health))
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("starting federation signer on {addr} (mTLS enabled)");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    let tls_config = load_tls_server_config(
        FsPath::new(&tls_cert_file),
        FsPath::new(&tls_key_file),
        Some(FsPath::new(&tls_ca_file)),
    )
    .expect("failed to build TLS server config");
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

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

            let client_cn = extract_client_cn(&tls_stream);

            let io = TokioIo::new(tls_stream);

            let tower_service = tower::service_fn(move |mut req: HyperRequest<Incoming>| {
                let app = app.clone();
                let client_cn = client_cn.clone();
                async move {
                    if let Some(cn) = client_cn.clone() {
                        req.extensions_mut().insert(ClientCertCn(cn));
                    }
                    app.clone().oneshot(req).await
                }
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

async fn round1_commit(
    State(state): State<AppState>,
    Json(req): Json<Round1CommitRequest>,
) -> impl IntoResponse {
    let mut guard = state.signer.lock().await;

    let (nonces, commitment) = match arcmint_core::frost_ops::generate_nonce_and_commitment(
        &guard.key_package,
        &mut rand::rngs::OsRng,
    ) {
        Ok(v) => v,
        Err(e) => {
            error!("round1 commit error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    guard
        .active_nonces
        .insert(req.session_id.clone(), (nonces, Instant::now()));

    let signer_id_label = signer_id_env();
    let count = guard.active_nonces.len() as f64;
    ACTIVE_NONCES_COUNT
        .with_label_values(&[&signer_id_label])
        .set(count);

    (StatusCode::OK, Json(commitment)).into_response()
}

async fn round2_sign(
    State(state): State<AppState>,
    Json(req): Json<Round2SignRequest>,
) -> impl IntoResponse {
    let mut guard = state.signer.lock().await;
    let start = Instant::now();

    let (nonces, _) = match guard.active_nonces.remove(&req.session_id) {
        Some(n) => n,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let partial = match arcmint_core::frost_ops::produce_partial_signature(
        &guard.key_package,
        &nonces,
        &req.message,
        &req.all_commitments,
    ) {
        Ok(p) => p,
        Err(e) => {
            error!("round2 sign error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let elapsed = start.elapsed().as_secs_f64();
    let signer_id_label = signer_id_env();
    FROST_ROUND_DURATION_SECONDS
        .with_label_values(&["2", &signer_id_label])
        .observe(elapsed);

    (StatusCode::OK, Json(partial)).into_response()
}

async fn run_nonce_cleanup(state: Arc<Mutex<SignerState>>, ttl_secs: u64) {
    let interval = Duration::from_secs(60);
    loop {
        tokio::time::sleep(interval).await;

        let now = Instant::now();
        let mut removed = 0usize;

        {
            let mut guard = state.lock().await;
            guard.active_nonces.retain(|_, (_, inserted_at)| {
                let expired = now
                    .checked_duration_since(*inserted_at)
                    .map(|d| d.as_secs() > ttl_secs)
                    .unwrap_or(false);
                if expired {
                    removed += 1;
                    false
                } else {
                    true
                }
            });
        }

        if removed > 0 {
            debug!("nonce cleanup removed {removed} expired entries");
        }
    }
}

async fn registry_issue(
    State(state): State<AppState>,
    Json(req): Json<IssueRequest>,
) -> impl IntoResponse {
    let signer = state.signer.lock().await;
    let start = Instant::now();

    let result = signer.issued.insert(&req.serial, req.denomination).await;
    let elapsed = start.elapsed().as_secs_f64();
    DB_WRITE_LATENCY_SECONDS
        .with_label_values(&["registry_issue"])
        .observe(elapsed);

    match result {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => {
            error!("issue registry error: {e:?}");
            StatusCode::CONFLICT.into_response()
        }
    }
}

async fn registry_spend(
    State(state): State<AppState>,
    Json(req): Json<SpendRegistryRequest>,
) -> impl IntoResponse {
    let signer = state.signer.lock().await;

    if let Some(second) = req.second_challenge {
        if let Some(theta) = req.theta_u {
            if theta.len() != 32 {
                return StatusCode::BAD_REQUEST.into_response();
            }
            let mut theta_arr = [0u8; 32];
            theta_arr.copy_from_slice(&theta);

            let start = Instant::now();
            let result = signer
                .spent
                .insert_second_spend(&req.serial, &second, &theta_arr)
                .await;
            let elapsed = start.elapsed().as_secs_f64();
            DB_WRITE_LATENCY_SECONDS
                .with_label_values(&["registry_spend_second"])
                .observe(elapsed);

            match result {
                Ok(Some((theta_bytes, c1, c2))) => {
                    DOUBLE_SPEND_ATTEMPTS_TOTAL.inc();
                    info!(
                        "double spend detected for serial {}; theta_u={:?} c1={:?} c2={:?}",
                        hex::encode(req.serial.0),
                        theta_bytes,
                        c1,
                        c2
                    );
                    StatusCode::OK.into_response()
                }
                Ok(None) => StatusCode::OK.into_response(),
                Err(e) => {
                    error!("spent registry second spend error: {e:?}");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        } else {
            StatusCode::BAD_REQUEST.into_response()
        }
    } else {
        let start = Instant::now();
        let result = signer
            .spent
            .insert_pending(&req.serial, &req.challenge)
            .await;
        let elapsed = start.elapsed().as_secs_f64();
        DB_WRITE_LATENCY_SECONDS
            .with_label_values(&["registry_spend_pending"])
            .observe(elapsed);

        match result {
            Ok(_) => StatusCode::OK.into_response(),
            Err(e) => {
                error!("spent registry insert error: {e:?}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

async fn registry_issued_get(
    State(state): State<AppState>,
    Path(serial_hex): Path<String>,
) -> impl IntoResponse {
    let signer = state.signer.lock().await;
    match hex_to_serial(&serial_hex) {
        Ok(serial) => match signer.issued.contains(&serial).await {
            Ok(true) => StatusCode::OK.into_response(),
            Ok(false) => StatusCode::NOT_FOUND.into_response(),
            Err(e) => {
                error!("issued registry lookup error: {e:?}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn registry_spent_get(
    State(state): State<AppState>,
    Path(serial_hex): Path<String>,
) -> impl IntoResponse {
    let signer = state.signer.lock().await;
    match hex_to_serial(&serial_hex) {
        Ok(serial) => match signer.spent.is_spent(&serial).await {
            Ok(true) => StatusCode::OK.into_response(),
            Ok(false) => StatusCode::NOT_FOUND.into_response(),
            Err(e) => {
                error!("spent registry lookup error: {e:?}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn audit(State(state): State<AppState>) -> impl IntoResponse {
    let signer = state.signer.lock().await;

    let issued_serials = match signer.issued.all_serials().await {
        Ok(v) => v,
        Err(e) => {
            error!("audit issued_serials error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let spent_count = match signer.spent.count().await {
        Ok(c) => c,
        Err(e) => {
            error!("audit spent count error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let issued_count = match signer.issued.count().await {
        Ok(c) => c,
        Err(e) => {
            error!("audit issued count error: {e:?}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let outstanding = issued_count.saturating_sub(spent_count);
    let empty_spent: [SerialNumber; 0] = [];
    let commitment = compute_state_commitment(&issued_serials, &empty_spent, 0);
    let issued_root = hex::encode(commitment.issued_root);
    let spent_root = hex::encode(commitment.spent_root);
    let response = AuditResponse {
        issued_count,
        spent_count,
        outstanding,
        issued_root,
        spent_root,
        anchored_at: None,
        anchor_hash: None,
        anchor_slot: None,
    };

    (StatusCode::OK, Json(response)).into_response()
}

async fn health() -> impl IntoResponse {
    StatusCode::OK
}

async fn metrics() -> impl IntoResponse {
    let body = render_metrics();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4".to_string(),
        )],
        body,
    )
}

fn signer_id_env() -> String {
    std::env::var("SIGNER_ID").unwrap_or_else(|_| "unknown".to_string())
}

#[derive(Clone)]
struct ClientCertCn(String);

fn extract_client_cn(tls_info: &TlsStream<TcpStream>) -> Option<String> {
    let (_io, conn) = tls_info.get_ref();
    let certs = conn.peer_certificates()?;
    let cert = certs.first()?;
    let der = cert.as_ref();
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(der) else {
        return None;
    };
    for cn in parsed.subject().iter_common_name() {
        if let Ok(value) = cn.as_str() {
            return Some(value.to_owned());
        }
    }
    None
}

async fn require_coordinator_cn(
    State(state): State<AppState>,
    req: Request,
    next: middleware::Next,
) -> impl IntoResponse {
    let client_cn = req
        .extensions()
        .get::<ClientCertCn>()
        .map(|wrapper| wrapper.0.clone());
    let expected = state.coordinator_cn.as_str();
    if client_cn.as_deref() != Some(expected) {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(req).await
}

fn hex_to_serial(s: &str) -> Result<SerialNumber, ()> {
    let bytes = match hex::decode(s) {
        Ok(b) => b,
        Err(_) => return Err(()),
    };
    if bytes.len() != 32 {
        return Err(());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SerialNumber(arr))
}
