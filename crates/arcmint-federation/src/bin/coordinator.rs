use arcmint_core::anchoring::bitcoin_rpc::{BitcoinRpcClient, BitcoinRpcConfig};
use arcmint_core::anchoring::tracker::{run_tracker_loop, AnchorTracker};
use arcmint_core::anchoring::tx_builder::AnchorTxBuilder;
use arcmint_core::anchoring::{encode_anchor_payload, AnchorPayload, AnchorRecord};
use arcmint_core::crypto::{generators, SerialNumber};
use arcmint_core::frost_ops::{
    aggregate_signatures, load_public_key_package, AggregatedSignature, PartialSignature,
    SignerIdentifier, SigningCommitment,
};
use arcmint_core::lightning::types::{InvoiceSettledEvent, InvoiceStatus};
use arcmint_core::lightning::{
    backend::LightningBackend, settlement::SettlementHandler, MintCommitmentPreimage,
    MintInSession, MintInState, MintOutSession, MintOutState,
};
use arcmint_core::metrics::{
    render_metrics, ACTIVE_SESSIONS_COUNT, ANCHOR_SLOT, ANCHOR_SUBMIT_TOTAL,
    CHANNEL_BALANCE_LOCAL_MSAT, CHANNEL_BALANCE_REMOTE_MSAT, INVOICE_SETTLEMENT_FAILURES_TOTAL,
    ISSUANCE_REQUESTS_TOTAL, LIGHTNING_PAYMENT_LATENCY_SECONDS, MINT_IN_TOTAL, MINT_OUT_TOTAL,
    SIGNER_RPC_LATENCY_SECONDS, SPEND_VERIFICATION_LATENCY_SECONDS,
};
use arcmint_core::note::{note_hash, NoteCommitmentData, SignedNote};
use arcmint_core::protocol::{
    AuditResponse, IssuanceChallenge, IssuanceRequest, IssuanceResponse, IssuanceReveal,
    MintInCommitment, MintInRequest, SpendChallenge, SpendProof, SpendRequest, SpendResponse,
};
use arcmint_core::recovery::{challenges_differ, recover_theta_u};
use arcmint_core::registry::{commitment_hash, MerkleCommitment};
use arcmint_core::spending::{
    verify_all_opened_candidates, verify_frost_signature, verify_spend_proof,
};
use arcmint_core::tls::{load_tls_client_config, load_tls_server_config};
use arcmint_lnd::{LndBackend, LndConfig};
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Json;
use frost_ristretto255::keys::PublicKeyPackage;
use futures::future::join_all;
use hyper::body::Incoming;
use hyper::Request as HyperRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use rand::prelude::SliceRandom;
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng};
use reqwest::Client;
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, Mutex};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Clone)]
struct CoordinatorSession {
    candidates: Vec<NoteCommitmentData>,
    open_indices: Vec<usize>,
    closed_index: usize,
    commitments: HashMap<String, SigningCommitment>,
    session_id: String,
    message: Vec<u8>,
    created_at: Instant,
}

#[derive(Clone)]
struct CoordinatorState {
    signer_urls: Vec<String>,
    public_key_package: PublicKeyPackage,
    active_sessions: HashMap<String, CoordinatorSession>,
    mint_in_sessions: HashMap<String, MintInSession>,
    mint_out_sessions: HashMap<SerialNumber, MintOutSession>,
    signer_client: Client,
    http_client: Client,
    gateway_resolve_url: String,
    anchor_records: Vec<AnchorRecord>,
    bitcoin_rpc_client: Option<BitcoinRpcClient>,
    anchor_tracker: AnchorTracker,
    anchor_fee_target_blocks: u32,
    anchor_interval_blocks: u32,
    anchor_min_confirmations: u32,
    anchor_change_address: Option<String>,
    anchor_interval_secs: u64,
    spend_challenges: HashMap<SerialNumber, Vec<u8>>,
    spend_notes: HashMap<SerialNumber, NoteCommitmentData>,
    spend_proofs: HashMap<SerialNumber, (SpendProof, Vec<u8>)>,
    session_ttl_secs: u64,
    settlement_tx: broadcast::Sender<InvoiceSettledEvent>,
    last_settle_index: Arc<Mutex<u64>>,
    lightning: Arc<dyn LightningBackend>,
    pool: SqlitePool,
}

#[derive(Clone)]
struct AppState {
    coordinator: Arc<Mutex<CoordinatorState>>,
    gateway_cn: String,
    operator_secret: String,
}

struct SpendVerifyTimer {
    start: Instant,
}

impl SpendVerifyTimer {
    fn new() -> Self {
        SpendVerifyTimer {
            start: Instant::now(),
        }
    }
}

impl Drop for SpendVerifyTimer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_secs_f64();
        SPEND_VERIFICATION_LATENCY_SECONDS.observe(elapsed);
    }
}

async fn observe_signer_rpc<F, T>(signer_id: &str, operation: &str, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let start = Instant::now();
    let out = fut.await;
    let elapsed = start.elapsed().as_secs_f64();
    SIGNER_RPC_LATENCY_SECONDS
        .with_label_values(&[signer_id, operation])
        .observe(elapsed);
    out
}

async fn metrics_handler() -> impl IntoResponse {
    let body = render_metrics();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

#[derive(Clone, serde::Serialize)]
struct Round1CommitRequest {
    session_id: String,
    message_hash: Vec<u8>,
}

#[derive(Clone, serde::Serialize)]
struct Round2SignRequest {
    session_id: String,
    message: Vec<u8>,
    all_commitments: Vec<(SignerIdentifier, SigningCommitment)>,
}

#[derive(Clone, serde::Serialize)]
struct RegistryIssueRequest {
    serial: SerialNumber,
    denomination: u64,
}

#[derive(Clone, serde::Serialize)]
struct RegistrySpendRequest {
    serial: SerialNumber,
    challenge: Vec<u8>,
    second_challenge: Option<Vec<u8>>,
    theta_u: Option<Vec<u8>>,
}

#[derive(serde::Serialize)]
struct GatewayResolveRequest {
    serial: SerialNumber,
    theta_u: Vec<u8>,
}

#[derive(serde::Deserialize, Debug)]
struct SpendVerifyRequest {
    serial: SerialNumber,
    proof: SpendProof,
    challenge_bits: Option<Vec<u8>>,
    note: Option<SignedNote>,
}

#[derive(serde::Deserialize)]
struct MintOutBeginRequest {
    serial: SerialNumber,
    payment_request: String,
}

#[derive(serde::Deserialize)]
struct MintInPollRequest {
    session_id: String,
}

#[derive(serde::Serialize)]
struct MintInPollResponse {
    status: String,
    signature: Option<Vec<u8>>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt().init();

    let port: u16 = env::var("COORDINATOR_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7000);

    let signer_urls_env =
        env::var("SIGNER_URLS").expect("SIGNER_URLS env var (comma-separated) must be set");
    let signer_urls: Vec<String> = signer_urls_env
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if signer_urls.is_empty() {
        panic!("SIGNER_URLS must contain at least one URL");
    }

    let pubkey_path = env::var("FROST_PUBKEY_FILE").expect("FROST_PUBKEY_FILE env var must be set");
    let public_key_package = load_public_key_package(FsPath::new(&pubkey_path))
        .expect("failed to load public key package from file");

    let coordinator_secret =
        env::var("COORDINATOR_SECRET").expect("COORDINATOR_SECRET env var must be set");
    let gateway_resolve_url =
        env::var("GATEWAY_RESOLVE_URL").expect("GATEWAY_RESOLVE_URL env var must be set");

    let coordinator_client_cert =
        env::var("COORDINATOR_CLIENT_CERT").expect("COORDINATOR_CLIENT_CERT env var must be set");
    let coordinator_client_key =
        env::var("COORDINATOR_CLIENT_KEY").expect("COORDINATOR_CLIENT_KEY env var must be set");
    let internal_ca_file =
        env::var("INTERNAL_CA_FILE").expect("INTERNAL_CA_FILE env var must be set");

    let gateway_cn = env::var("GATEWAY_CN").unwrap_or_else(|_| "arcmint-gateway".to_string());
    let operator_secret =
        env::var("OPERATOR_SECRET").unwrap_or_else(|_| coordinator_secret.clone());

    let bitcoin_rpc_client = if let Ok(url) = env::var("BITCOIN_RPC_URL") {
        let user = env::var("BITCOIN_RPC_USER").unwrap_or_else(|_| "arcmint".to_string());
        let password = env::var("BITCOIN_RPC_PASS").unwrap_or_else(|_| "password".to_string());
        let wallet_name = env::var("BITCOIN_WALLET_NAME").unwrap_or_else(|_| "anchor".to_string());

        let config = BitcoinRpcConfig {
            url,
            user,
            password,
            wallet_name,
        };
        Some(BitcoinRpcClient::new(config).expect("failed to create bitcoin rpc client"))
    } else {
        None
    };

    let anchor_interval_secs: u64 = env::var("ANCHOR_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600);
    let session_ttl_secs: u64 = env::var("SESSION_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    let anchor_fee_target_blocks: u32 = env::var("ANCHOR_FEE_TARGET_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let anchor_interval_blocks: u32 = env::var("ANCHOR_INTERVAL_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);
    let anchor_min_confirmations: u32 = env::var("ANCHOR_MIN_CONFIRMATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let anchor_change_address = env::var("ANCHOR_CHANGE_ADDRESS").ok();

    let db_path = env::var("COORDINATOR_DB").unwrap_or_else(|_| "coordinator.db".to_string());
    let db_url = if db_path.starts_with("sqlite:") {
        db_path
    } else {
        format!("sqlite://{}", db_path)
    };

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("failed to connect to SQLite for coordinator");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS settle_index (
             id INTEGER PRIMARY KEY,
             idx INTEGER NOT NULL DEFAULT 0
         )",
    )
    .execute(&pool)
    .await
    .expect("failed to init coordinator settle_index schema");

    let row = sqlx::query("SELECT idx FROM settle_index WHERE id = 1")
        .fetch_optional(&pool)
        .await
        .expect("failed to query coordinator settle_index");

    let initial_settle_index: u64 = if let Some(row) = row {
        let value: i64 = row
            .try_get("idx")
            .expect("failed to read idx from settle_index");
        if value < 0 {
            0
        } else {
            value as u64
        }
    } else {
        sqlx::query("INSERT INTO settle_index (id, idx) VALUES (1, 0)")
            .execute(&pool)
            .await
            .expect("failed to initialize coordinator settle_index");
        0
    };

    let signer_tls_config = load_tls_client_config(
        FsPath::new(&internal_ca_file),
        Some(FsPath::new(&coordinator_client_cert)),
        Some(FsPath::new(&coordinator_client_key)),
    )
    .expect("failed to build coordinator mTLS client config for signers");

    let signer_client = Client::builder()
        .use_preconfigured_tls(signer_tls_config)
        .build()
        .expect("failed to build mTLS HTTP client for signers");

    let http_client = Client::new();

    let lnd_host = env::var("LND_HOST").unwrap_or_else(|_| "localhost".to_string());
    let lnd_port: u16 = env::var("LND_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10009);
    let lnd_tls_cert = env::var("LND_TLS_CERT").expect("LND_TLS_CERT env var must be set");
    let lnd_macaroon = env::var("LND_MACAROON").expect("LND_MACAROON env var must be set");

    let lnd_config = LndConfig {
        host: lnd_host,
        port: lnd_port,
        tls_cert_path: FsPath::new(&lnd_tls_cert).to_path_buf(),
        macaroon_path: FsPath::new(&lnd_macaroon).to_path_buf(),
    };

    let lightning_backend = LndBackend::connect(lnd_config)
        .await
        .expect("failed to connect to LND");
    let lightning: Arc<dyn LightningBackend> = Arc::new(lightning_backend);

    let (settlement_handler, settlement_rx) = SettlementHandler::new();
    let settlement_tx = settlement_handler.sender();
    let last_settle_index = Arc::new(Mutex::new(initial_settle_index));

    let anchor_tracker = AnchorTracker::new(pool.clone());
    anchor_tracker
        .init_table()
        .await
        .expect("failed to init anchor table");

    if let Some(rpc) = bitcoin_rpc_client.clone() {
        let tracker = anchor_tracker.clone();
        tokio::spawn(async move {
            run_tracker_loop(tracker, rpc, 60).await;
        });
    }

    let state = CoordinatorState {
        signer_urls,
        public_key_package,
        active_sessions: HashMap::new(),
        mint_in_sessions: HashMap::new(),
        mint_out_sessions: HashMap::new(),
        signer_client,
        http_client,
        gateway_resolve_url,
        anchor_records: Vec::new(),
        bitcoin_rpc_client,
        anchor_tracker,
        anchor_fee_target_blocks,
        anchor_interval_blocks,
        anchor_min_confirmations,
        anchor_change_address,
        anchor_interval_secs,
        spend_challenges: HashMap::new(),
        spend_notes: HashMap::new(),
        spend_proofs: HashMap::new(),
        session_ttl_secs,
        settlement_tx: settlement_tx.clone(),
        last_settle_index: last_settle_index.clone(),
        lightning: lightning.clone(),
        pool: pool.clone(),
    };

    let shared_state = AppState {
        coordinator: Arc::new(Mutex::new(state)),
        gateway_cn,
        operator_secret,
    };

    let settlement_state_for_handler = shared_state.coordinator.clone();
    tokio::spawn(async move {
        let (lightning, settlement_tx, last_index_arc) = {
            let guard = settlement_state_for_handler.lock().await;
            (
                guard.lightning.clone(),
                guard.settlement_tx.clone(),
                guard.last_settle_index.clone(),
            )
        };
        let start_index = {
            let idx = last_index_arc.lock().await;
            *idx
        };
        SettlementHandler::run(lightning, settlement_tx, start_index).await;
    });

    let settlement_state = shared_state.coordinator.clone();
    tokio::spawn(async move {
        run_settlement_persistence(settlement_state, settlement_rx).await;
    });

    let anchor_state = shared_state.coordinator.clone();
    tokio::spawn(run_anchor_loop(anchor_state.clone()));

    let channel_balance_state = shared_state.coordinator.clone();
    tokio::spawn(run_channel_balance_loop(channel_balance_state));

    let cleanup_state = shared_state.coordinator.clone();
    tokio::spawn(run_session_cleanup(cleanup_state));

    let gateway_auth_layer =
        middleware::from_fn_with_state(shared_state.clone(), require_gateway_cn);
    let operator_auth_layer =
        middleware::from_fn_with_state(shared_state.clone(), require_operator_secret);

    let app = axum::Router::new()
        .route(
            "/issue/begin",
            post(issue_begin).route_layer(gateway_auth_layer.clone()),
        )
        .route(
            "/issue/reveal",
            post(issue_reveal).route_layer(gateway_auth_layer.clone()),
        )
        .route("/registry/issued/:serial", get(registry_issued_proxy))
        .route(
            "/spend/challenge",
            post(spend_challenge).route_layer(gateway_auth_layer.clone()),
        )
        .route(
            "/spend/verify",
            post(spend_verify).route_layer(gateway_auth_layer.clone()),
        )
        .route(
            "/mint/in/begin",
            post(mint_in_begin).route_layer(gateway_auth_layer.clone()),
        )
        .route(
            "/mint/in/poll",
            post(mint_in_poll).route_layer(gateway_auth_layer.clone()),
        )
        .route(
            "/mint/out/begin",
            post(mint_out_begin).route_layer(gateway_auth_layer.clone()),
        )
        .route("/metrics", get(metrics_handler))
        .route(
            "/anchors",
            get(anchors).route_layer(operator_auth_layer.clone()),
        )
        .route("/audit", get(audit).route_layer(operator_auth_layer))
        .route("/health", get(health))
        .with_state(shared_state);

    let coordinator_tls_cert =
        env::var("COORDINATOR_TLS_CERT").expect("COORDINATOR_TLS_CERT env var must be set");
    let coordinator_tls_key =
        env::var("COORDINATOR_TLS_KEY").expect("COORDINATOR_TLS_KEY env var must be set");
    let gateway_client_ca =
        env::var("GATEWAY_CLIENT_CA").expect("GATEWAY_CLIENT_CA env var must be set");

    let tls_server_config = load_tls_server_config(
        FsPath::new(&coordinator_tls_cert),
        FsPath::new(&coordinator_tls_key),
        Some(FsPath::new(&gateway_client_ca)),
    )
    .expect("failed to build coordinator TLS server config");
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_server_config));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("starting coordinator on {addr} (mTLS enabled)");

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

async fn registry_issued_proxy(
    State(state): State<AppState>,
    Path(serial): Path<String>,
) -> impl IntoResponse {
    let (signer_urls, client) = {
        let guard = state.coordinator.lock().await;
        (guard.signer_urls.clone(), guard.signer_client.clone())
    };

    let futures = signer_urls.iter().enumerate().map(|(idx, url)| {
        let client = client.clone();
        let serial = serial.clone();
        let url = url.clone();
        async move {
            let full_url = format!("{url}/registry/issued/{serial}");
            let signer_id = format!("signer-{idx}");
            observe_signer_rpc(&signer_id, "registry_issued_get", async {
                client.get(&full_url).send().await
            })
            .await
        }
    });

    let results = join_all(futures).await;
    let mut yes = 0;
    for resp in results.into_iter().flatten() {
        if resp.status().is_success() {
            yes += 1;
        }
    }

    let threshold = signer_urls.len().div_ceil(2);
    if yes >= threshold {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

#[axum::debug_handler]
async fn issue_begin(
    State(state): State<AppState>,
    Json(req): Json<IssuanceRequest>,
) -> impl IntoResponse {
    if req.blinded_candidates.is_empty() {
        ISSUANCE_REQUESTS_TOTAL
            .with_label_values(&["rejected"])
            .inc();
        return StatusCode::BAD_REQUEST.into_response();
    }

    let k = req.blinded_candidates.len();
    let (closed_index, open_indices): (usize, Vec<usize>) = {
        let mut rng: ThreadRng = thread_rng();
        let closed_index = rng.gen_range(0..k);
        let mut open_indices: Vec<usize> = (0..k).filter(|i| *i != closed_index).collect();
        open_indices.shuffle(&mut rng);
        (closed_index, open_indices)
    };

    let closed_candidate = req.blinded_candidates[closed_index].clone();
    if closed_candidate.denomination == 0 {
        ISSUANCE_REQUESTS_TOTAL
            .with_label_values(&["rejected"])
            .inc();
        return StatusCode::BAD_REQUEST.into_response();
    }

    let message = note_hash(&closed_candidate);
    let message_hash = hash_message(&message);

    let session_id = Uuid::new_v4().to_string();

    let (signer_urls, client) = {
        let guard = state.coordinator.lock().await;
        (guard.signer_urls.clone(), guard.signer_client.clone())
    };

    let commit_req = Round1CommitRequest {
        session_id: session_id.clone(),
        message_hash,
    };

    let futures = signer_urls.into_iter().enumerate().map(|(idx, url)| {
        let client = client.clone();
        let body = commit_req.clone();
        async move {
            let full_url = format!("{url}/round1/commit");
            let signer_id = format!("signer-{idx}");
            let res = observe_signer_rpc(&signer_id, "round1_commit", async {
                client.post(&full_url).json(&body).send().await
            })
            .await;
            match res {
                Ok(resp) if resp.status().is_success() => resp
                    .json::<SigningCommitment>()
                    .await
                    .map_err(|e| e.to_string()),
                Ok(resp) => Err(format!("round1 commit HTTP {}", resp.status())),
                Err(e) => Err(format!("round1 commit request error: {e}")),
            }
        }
    });

    let results = join_all(futures).await;

    let mut commitments = HashMap::new();
    for (idx, result) in results.into_iter().enumerate() {
        match result {
            Ok(c) => {
                commitments.insert(format!("signer-{idx}"), c);
            }
            Err(e) => {
                error!("round1 commit failed for signer {idx}: {e}");
                ISSUANCE_REQUESTS_TOTAL.with_label_values(&["failed"]).inc();
                return StatusCode::BAD_GATEWAY.into_response();
            }
        }
    }

    let session = CoordinatorSession {
        candidates: req.blinded_candidates,
        open_indices: open_indices.clone(),
        closed_index,
        commitments,
        session_id: session_id.clone(),
        message: message.to_vec(),
        created_at: Instant::now(),
    };

    {
        let mut guard = state.coordinator.lock().await;
        guard.active_sessions.insert(session_id.clone(), session);
        ACTIVE_SESSIONS_COUNT.set(guard.active_sessions.len() as f64);
    }

    let challenge = IssuanceChallenge {
        session_id,
        open_indices,
    };

    ISSUANCE_REQUESTS_TOTAL
        .with_label_values(&["success"])
        .inc();

    (StatusCode::OK, Json(challenge)).into_response()
}

async fn issue_reveal(
    State(state): State<AppState>,
    Json(req): Json<IssuanceReveal>,
) -> impl IntoResponse {
    info!(
        "issue_reveal start session_id={} revealed_count={}",
        req.session_id,
        req.revealed.len()
    );
    let (session, signer_urls, client, public_key_package) = {
        let mut guard = state.coordinator.lock().await;

        let session = match guard.active_sessions.remove(&req.session_id) {
            Some(s) => s,
            None => return StatusCode::NOT_FOUND.into_response(),
        };

        ACTIVE_SESSIONS_COUNT.set(guard.active_sessions.len() as f64);

        ACTIVE_SESSIONS_COUNT.set(guard.active_sessions.len() as f64);

        (
            session,
            guard.signer_urls.clone(),
            guard.signer_client.clone(),
            guard.public_key_package.clone(),
        )
    };

    info!("issue_reveal loaded session");

    if session.candidates.is_empty() {
        ISSUANCE_REQUESTS_TOTAL
            .with_label_values(&["rejected"])
            .inc();
        return StatusCode::BAD_REQUEST.into_response();
    }

    let (g, h) = generators();

    if let Err(e) = verify_all_opened_candidates(
        &session.candidates,
        &req.revealed,
        &session.open_indices,
        &g,
        &h,
    ) {
        error!("opened candidate verification failed: {e:?}");
        ISSUANCE_REQUESTS_TOTAL
            .with_label_values(&["rejected"])
            .inc();
        return StatusCode::BAD_REQUEST.into_response();
    }

    info!("issue_reveal candidates verified");

    let mut check_futures = Vec::with_capacity(req.revealed.len() * signer_urls.len());
    for reveal in &req.revealed {
        let serial_hex = hex::encode(reveal.serial.0);
        for (idx, url) in signer_urls.iter().enumerate() {
            let client = client.clone();
            let serial = serial_hex.clone();
            let url = url.clone();
            check_futures.push(async move {
                let full_url = format!("{url}/registry/issued/{serial}");
                let signer_id = format!("signer-{idx}");
                observe_signer_rpc(&signer_id, "registry_issued_check", async {
                    client.get(&full_url).send().await
                })
                .await
            });
        }
    }

    let responses = join_all(check_futures).await;
    for resp in responses {
        match resp {
            Ok(r) if r.status().is_success() => {
                return StatusCode::CONFLICT.into_response();
            }
            Ok(_) => {}
            Err(e) => {
                error!("issued uniqueness check error: {e}");
                ISSUANCE_REQUESTS_TOTAL.with_label_values(&["failed"]).inc();
                return StatusCode::BAD_GATEWAY.into_response();
            }
        }
    }

    info!("issue_reveal uniqueness check complete");

    let closed_candidate = session.candidates[session.closed_index].clone();

    let mut all_commitments = Vec::with_capacity(session.commitments.len());
    for c in session.commitments.values() {
        all_commitments.push((c.signer_id.clone(), c.clone()));
    }

    let sign_req = Round2SignRequest {
        session_id: session.session_id.clone(),
        message: session.message.clone(),
        all_commitments: all_commitments.clone(),
    };

    let futures = signer_urls.iter().enumerate().map(|(idx, url)| {
        let client = client.clone();
        let body = sign_req.clone();
        let url = url.clone();
        async move {
            let full_url = format!("{url}/round2/sign");
            let signer_id = format!("signer-{idx}");
            let res = observe_signer_rpc(&signer_id, "round2_sign", async {
                client.post(&full_url).json(&body).send().await
            })
            .await;
            match res {
                Ok(resp) if resp.status().is_success() => resp
                    .json::<PartialSignature>()
                    .await
                    .map_err(|e| e.to_string()),
                Ok(resp) => Err(format!("round2 sign HTTP {}", resp.status())),
                Err(e) => Err(format!("round2 sign request error: {e}")),
            }
        }
    });

    info!("issue_reveal sending round2 sign requests");
    let results = join_all(futures).await;
    let mut partials = Vec::new();
    for (idx, result) in results.into_iter().enumerate() {
        match result {
            Ok(p) => partials.push(p),
            Err(e) => {
                error!("round2 sign failed for signer {idx}: {e}");
                ISSUANCE_REQUESTS_TOTAL.with_label_values(&["failed"]).inc();
                return StatusCode::BAD_GATEWAY.into_response();
            }
        }
    }

    info!("issue_reveal collected partial signatures, aggregating");

    let aggregated: AggregatedSignature = match aggregate_signatures(
        &session.message,
        &all_commitments,
        &partials,
        &public_key_package,
    ) {
        Ok(sig) => sig,
        Err(e) => {
            error!("aggregate_signatures error: {e:?}");
            ISSUANCE_REQUESTS_TOTAL.with_label_values(&["failed"]).inc();
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let signed_note = SignedNote {
        data: closed_candidate.clone(),
        signature: aggregated.0.clone(),
    };

    let registry_req = RegistryIssueRequest {
        serial: closed_candidate.serial,
        denomination: closed_candidate.denomination,
    };

    let registry_futures = signer_urls.into_iter().map(|url| {
        let client = client.clone();
        let body = registry_req.clone();
        async move {
            let full_url = format!("{url}/registry/issue");
            client.post(&full_url).json(&body).send().await
        }
    });

    info!("issue_reveal sending registry issue requests");
    let registry_results = join_all(registry_futures).await;
    for (idx, res) in registry_results.into_iter().enumerate() {
        match res {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => {
                error!(
                    "registry issue failed for signer {idx}: HTTP {}",
                    resp.status()
                );
                return StatusCode::BAD_GATEWAY.into_response();
            }
            Err(e) => {
                error!("registry issue request error for signer {idx}: {e}");
                return StatusCode::BAD_GATEWAY.into_response();
            }
        }
    }

    info!("issue_reveal registry writes complete");
    let response = IssuanceResponse { signed_note };

    info!("issue_reveal completed successfully");
    ISSUANCE_REQUESTS_TOTAL
        .with_label_values(&["success"])
        .inc();
    (StatusCode::OK, Json(response)).into_response()
}

#[axum::debug_handler]
async fn mint_in_begin(
    State(state): State<AppState>,
    Json(req): Json<MintInRequest>,
) -> impl IntoResponse {
    if req.denomination_msat == 0 {
        MINT_IN_TOTAL.with_label_values(&["rejected"]).inc();
        return StatusCode::BAD_REQUEST.into_response();
    }
    if req.note_hash.len() != 32 {
        MINT_IN_TOTAL.with_label_values(&["rejected"]).inc();
        return StatusCode::BAD_REQUEST.into_response();
    }

    let note_hash_arr = match to_array32(&req.note_hash) {
        Some(arr) => arr,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let (lightning, public_key_package) = {
        let guard = state.coordinator.lock().await;
        (guard.lightning.clone(), guard.public_key_package.clone())
    };

    let balance = match lightning.get_channel_balance().await {
        Ok(b) => b,
        Err(_) => {
            MINT_IN_TOTAL.with_label_values(&["failed"]).inc();
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    if balance.local_msat < req.denomination_msat {
        MINT_IN_TOTAL.with_label_values(&["failed"]).inc();
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    let invoice = match lightning
        .create_invoice(req.denomination_msat, "arcmint mint-in", 600)
        .await
    {
        Ok(inv) => inv,
        Err(_) => {
            MINT_IN_TOTAL.with_label_values(&["failed"]).inc();
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    let session_id = Uuid::new_v4().to_string();

    let pubkey_bytes = public_key_package.verifying_key().serialize().to_vec();

    let preimage = MintCommitmentPreimage {
        note_hash: note_hash_arr,
        session_id: session_id.clone(),
        pubkey_bytes,
    };
    let mint_commitment = arcmint_core::lightning::compute_mint_commitment(&preimage);

    let session = MintInSession {
        note_hash: note_hash_arr,
        session_id: session_id.clone(),
        mint_commitment,
        payment_hash: invoice.payment_hash,
        payment_request: invoice.payment_request.clone(),
        denomination_msat: req.denomination_msat,
        state: MintInState::AwaitingPayment,
        created_at: std::time::Instant::now(),
        signature: None,
    };

    {
        let mut guard = state.coordinator.lock().await;
        guard.mint_in_sessions.insert(session_id.clone(), session);
    }

    let response = MintInCommitment {
        mint_commitment: mint_commitment.to_vec(),
        session_id,
        payment_request: invoice.payment_request,
        payment_hash: invoice.payment_hash.to_vec(),
    };

    MINT_IN_TOTAL.with_label_values(&["success"]).inc();

    (StatusCode::OK, Json(response)).into_response()
}

async fn run_mint_in_signing(
    state: Arc<Mutex<CoordinatorState>>,
    session_id: String,
) -> Result<Vec<u8>, ()> {
    let (note_hash, signer_urls, client, public_key_package, stored_session_id) = {
        let mut guard = state.lock().await;
        let signer_urls = guard.signer_urls.clone();
        let client = guard.signer_client.clone();
        let public_key_package = guard.public_key_package.clone();
        let session = match guard.mint_in_sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return Err(()),
        };
        match session.state {
            MintInState::AwaitingPayment => {
                session.state = MintInState::HtlcOpen;
            }
            MintInState::HtlcOpen | MintInState::Signed => {
                if let Some(sig) = session.signature.clone() {
                    return Ok(sig);
                } else {
                    return Err(());
                }
            }
            MintInState::Expired => {
                return Err(());
            }
        }
        (
            session.note_hash,
            signer_urls,
            client,
            public_key_package,
            session.session_id.clone(),
        )
    };

    let message = note_hash.to_vec();
    let message_hash = hash_message(&message);

    let commit_req = Round1CommitRequest {
        session_id: stored_session_id.clone(),
        message_hash,
    };

    let futures = signer_urls.iter().enumerate().map(|(idx, url)| {
        let client = client.clone();
        let body = commit_req.clone();
        let url = url.clone();
        async move {
            let full_url = format!("{url}/round1/commit");
            let signer_id = format!("signer-{idx}");
            let res = observe_signer_rpc(&signer_id, "round1_commit", async {
                client.post(&full_url).json(&body).send().await
            })
            .await;
            match res {
                Ok(resp) if resp.status().is_success() => resp
                    .json::<SigningCommitment>()
                    .await
                    .map_err(|e| e.to_string()),
                Ok(resp) => Err(format!("round1 commit HTTP {}", resp.status())),
                Err(e) => Err(format!("round1 commit request error: {e}")),
            }
        }
    });

    let results = join_all(futures).await;

    let mut commitments = HashMap::new();
    for (idx, result) in results.into_iter().enumerate() {
        match result {
            Ok(c) => {
                commitments.insert(format!("signer-{idx}"), c);
            }
            Err(e) => {
                error!("mint_in_signing round1 failed for signer {idx}: {e}");
                return Err(());
            }
        }
    }

    let mut all_commitments = Vec::with_capacity(commitments.len());
    for c in commitments.values() {
        all_commitments.push((c.signer_id.clone(), c.clone()));
    }

    let sign_req = Round2SignRequest {
        session_id: stored_session_id.clone(),
        message: message.clone(),
        all_commitments: all_commitments.clone(),
    };

    let futures = signer_urls.iter().enumerate().map(|(idx, url)| {
        let client = client.clone();
        let body = sign_req.clone();
        let url = url.clone();
        async move {
            let full_url = format!("{url}/round2/sign");
            let signer_id = format!("signer-{idx}");
            let res = observe_signer_rpc(&signer_id, "round2_sign", async {
                client.post(&full_url).json(&body).send().await
            })
            .await;
            match res {
                Ok(resp) if resp.status().is_success() => resp
                    .json::<PartialSignature>()
                    .await
                    .map_err(|e| e.to_string()),
                Ok(resp) => Err(format!("round2 sign HTTP {}", resp.status())),
                Err(e) => Err(format!("round2 sign request error: {e}")),
            }
        }
    });

    let results = join_all(futures).await;
    let mut partials = Vec::new();
    for (idx, result) in results.into_iter().enumerate() {
        match result {
            Ok(p) => partials.push(p),
            Err(e) => {
                error!("mint_in_signing round2 failed for signer {idx}: {e}");
                return Err(());
            }
        }
    }

    let aggregated: AggregatedSignature =
        match aggregate_signatures(&message, &all_commitments, &partials, &public_key_package) {
            Ok(sig) => sig,
            Err(e) => {
                error!("mint_in_signing aggregate_signatures error: {e:?}");
                return Err(());
            }
        };

    {
        let mut guard = state.lock().await;
        if let Some(s) = guard.mint_in_sessions.get_mut(&session_id) {
            s.state = MintInState::Signed;
            s.signature = Some(aggregated.0.clone());
        }
    }

    Ok(aggregated.0.clone())
}

#[axum::debug_handler]
async fn mint_in_poll(
    State(state): State<AppState>,
    Json(req): Json<MintInPollRequest>,
) -> impl IntoResponse {
    let (session_opt, lightning) = {
        let guard = state.coordinator.lock().await;
        (
            guard.mint_in_sessions.get(&req.session_id).cloned(),
            guard.lightning.clone(),
        )
    };

    let Some(session) = session_opt else {
        return StatusCode::NOT_FOUND.into_response();
    };

    if let MintInState::Signed = session.state {
        let response = MintInPollResponse {
            status: "ready".to_string(),
            signature: session.signature.clone(),
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    if session.created_at.elapsed().as_secs() > 600 && !matches!(session.state, MintInState::Signed)
    {
        {
            let mut guard = state.coordinator.lock().await;
            if let Some(s) = guard.mint_in_sessions.get_mut(&req.session_id) {
                s.state = MintInState::Expired;
            }
        }
        let response = MintInPollResponse {
            status: "expired".to_string(),
            signature: None,
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    if let MintInState::AwaitingPayment = session.state {
        let created_at = session.created_at;
        let lookup = lightning.lookup_invoice(&session.payment_hash).await;
        match lookup {
            Ok(InvoiceStatus::Settled { .. }) => {
                let elapsed = created_at.elapsed().as_secs_f64();
                LIGHTNING_PAYMENT_LATENCY_SECONDS.observe(elapsed);
                let signing_result =
                    run_mint_in_signing(state.coordinator.clone(), req.session_id.clone()).await;
                match signing_result {
                    Ok(sig) => {
                        let response = MintInPollResponse {
                            status: "ready".to_string(),
                            signature: Some(sig),
                        };
                        return (StatusCode::OK, Json(response)).into_response();
                    }
                    Err(_) => {
                        return StatusCode::BAD_GATEWAY.into_response();
                    }
                }
            }
            Ok(InvoiceStatus::Open) | Ok(InvoiceStatus::Accepted) => {
                let response = MintInPollResponse {
                    status: "pending".to_string(),
                    signature: None,
                };
                return (StatusCode::OK, Json(response)).into_response();
            }
            Ok(InvoiceStatus::Cancelled) => {
                INVOICE_SETTLEMENT_FAILURES_TOTAL.inc();
                let mut guard = state.coordinator.lock().await;
                if let Some(s) = guard.mint_in_sessions.get_mut(&req.session_id) {
                    s.state = MintInState::Expired;
                }
                let response = MintInPollResponse {
                    status: "expired".to_string(),
                    signature: None,
                };
                return (StatusCode::OK, Json(response)).into_response();
            }
            Err(_) => {
                INVOICE_SETTLEMENT_FAILURES_TOTAL.inc();
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        }
    }

    let response = MintInPollResponse {
        status: "pending".to_string(),
        signature: None,
    };
    (StatusCode::OK, Json(response)).into_response()
}

#[axum::debug_handler]
async fn spend_challenge(
    State(state): State<AppState>,
    Json(req): Json<SpendRequest>,
) -> impl IntoResponse {
    let signed = req.note;
    let data = signed.data.clone();

    let (public_key_package, signer_urls, client) = {
        let guard = state.coordinator.lock().await;
        (
            guard.public_key_package.clone(),
            guard.signer_urls.clone(),
            guard.signer_client.clone(),
        )
    };

    if let Err(e) = verify_frost_signature(&data, &signed.signature, &public_key_package) {
        error!("FROST signature verification failed: {e:?}");
        let response = SpendResponse {
            accepted: false,
            reason: Some("invalid signature".to_string()),
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    let serial_hex = hex::encode(data.serial.0);

    let issued_futures = signer_urls.iter().enumerate().map(|(idx, url)| {
        let client = client.clone();
        let serial = serial_hex.clone();
        let url = url.clone();
        async move {
            let full_url = format!("{url}/registry/issued/{serial}");
            let signer_id = format!("signer-{idx}");
            observe_signer_rpc(&signer_id, "registry_issued_check", async {
                client.get(&full_url).send().await
            })
            .await
        }
    });

    let issued_results = join_all(issued_futures).await;
    let mut issued_confirmations = 0usize;
    let total_signers = issued_results.len();

    for res in issued_results {
        match res {
            Ok(resp) if resp.status().is_success() => {
                issued_confirmations += 1;
            }
            Ok(_) => {}
            Err(e) => {
                error!("issued registry check error: {e}");
                let response = SpendResponse {
                    accepted: false,
                    reason: Some("upstream registry error".to_string()),
                };
                return (StatusCode::OK, Json(response)).into_response();
            }
        }
    }

    if issued_confirmations * 2 <= total_signers {
        let response = SpendResponse {
            accepted: false,
            reason: Some("note not issued by majority".to_string()),
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    let spent_futures = signer_urls.iter().enumerate().map(|(idx, url)| {
        let client = client.clone();
        let serial = serial_hex.clone();
        let url = url.clone();
        async move {
            let full_url = format!("{url}/registry/spent/{serial}");
            let signer_id = format!("signer-{idx}");
            observe_signer_rpc(&signer_id, "registry_spent_check", async {
                client.get(&full_url).send().await
            })
            .await
        }
    });

    let spent_results = join_all(spent_futures).await;
    for res in spent_results {
        match res {
            Ok(resp) if resp.status().is_success() => {
                let response = SpendResponse {
                    accepted: false,
                    reason: Some("note already spent".to_string()),
                };
                return (StatusCode::OK, Json(response)).into_response();
            }
            Ok(_) => {}
            Err(e) => {
                error!("spent registry check error: {e}");
                let response = SpendResponse {
                    accepted: false,
                    reason: Some("upstream registry error".to_string()),
                };
                return (StatusCode::OK, Json(response)).into_response();
            }
        }
    }

    let k = data.pairs.len();
    let challenge_bits = {
        let mut rng = thread_rng();
        let mut bits = Vec::with_capacity(k);
        for _ in 0..k {
            let bit: u8 = rng.gen_range(0..=1);
            bits.push(bit);
        }
        bits
    };
    {
        let mut guard = state.coordinator.lock().await;
        guard
            .spend_challenges
            .insert(data.serial, challenge_bits.clone());
        guard.spend_notes.insert(data.serial, data.clone());
    }

    let response = SpendChallenge {
        challenge_bits: challenge_bits.clone(),
    };

    (StatusCode::OK, Json(response)).into_response()
}

async fn spend_verify(
    State(state): State<AppState>,
    Json(req): Json<SpendVerifyRequest>,
) -> impl IntoResponse {
    let _timer = SpendVerifyTimer::new();
    if req.serial != req.proof.serial {
        let response = SpendResponse {
            accepted: false,
            reason: Some("serial mismatch".to_string()),
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    info!(
        "received spend_verify for serial {}",
        hex::encode(req.serial.0)
    );

    let (challenge_bits, note_data, maybe_first) = {
        let guard = state.coordinator.lock().await;

        let challenge_bits = if let Some(bits) = &req.challenge_bits {
            bits.clone()
        } else {
            match guard.spend_challenges.get(&req.serial) {
                Some(c) => c.clone(),
                None => {
                    let response = SpendResponse {
                        accepted: false,
                        reason: Some("unknown spend challenge".to_string()),
                    };
                    return (StatusCode::OK, Json(response)).into_response();
                }
            }
        };

        let note_data = if let Some(signed) = &req.note {
            signed.data.clone()
        } else {
            match guard.spend_notes.get(&req.serial) {
                Some(d) => d.clone(),
                None => {
                    let response = SpendResponse {
                        accepted: false,
                        reason: Some("unknown note data".to_string()),
                    };
                    return (StatusCode::OK, Json(response)).into_response();
                }
            }
        };

        let maybe_first = guard.spend_proofs.get(&req.serial).cloned();

        (challenge_bits, note_data, maybe_first)
    };

    let (g, h) = generators();

    if let Err(e) = verify_spend_proof(&note_data, &req.proof, &challenge_bits, &g, &h) {
        error!("spend proof verification failed: {e:?}");
        let response = SpendResponse {
            accepted: false,
            reason: Some(format!("invalid spend proof: {e:?}")),
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    let k = note_data.pairs.len();

    let theta_u = if let Some((first_proof, first_challenge)) = maybe_first {
        if challenges_differ(&first_challenge, &challenge_bits) {
            match recover_theta_u(
                &first_proof,
                &first_challenge,
                &req.proof,
                &challenge_bits,
                k,
            ) {
                Ok(theta) => {
                    info!(
                        "double spend detected for serial {}; recovered theta_u={:?}",
                        hex::encode(req.serial.0),
                        theta
                    );

                    let resolve_req = GatewayResolveRequest {
                        serial: req.serial,
                        theta_u: theta.to_vec(),
                    };

                    let (client, url) = {
                        let guard = state.coordinator.lock().await;
                        (guard.http_client.clone(), guard.gateway_resolve_url.clone())
                    };
                    tokio::spawn(async move {
                        if let Err(e) = client.post(&url).json(&resolve_req).send().await {
                            error!("failed to send resolve request to gateway: {e}");
                        }
                    });

                    Some(theta.to_vec())
                }
                Err(e) => {
                    error!("recover_theta_u failed: {e:?}");
                    None
                }
            }
        } else {
            None
        }
    } else {
        let mut guard = state.coordinator.lock().await;
        guard
            .spend_proofs
            .insert(req.serial, (req.proof.clone(), challenge_bits.clone()));
        None
    };

    let registry_req = RegistrySpendRequest {
        serial: req.serial,
        challenge: challenge_bits.clone(),
        second_challenge: theta_u.as_ref().map(|_| challenge_bits.clone()),
        theta_u: theta_u.clone(),
    };

    let (signer_urls, client) = {
        let guard = state.coordinator.lock().await;
        (guard.signer_urls.clone(), guard.signer_client.clone())
    };

    let futures = signer_urls.into_iter().enumerate().map(|(idx, url)| {
        let client = client.clone();
        let body = registry_req.clone();
        async move {
            let full_url = format!("{url}/registry/spend");
            let signer_id = format!("signer-{idx}");
            observe_signer_rpc(&signer_id, "registry_spend", async {
                client.post(&full_url).json(&body).send().await
            })
            .await
        }
    });

    let results = join_all(futures).await;
    for (idx, res) in results.into_iter().enumerate() {
        match res {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => {
                error!(
                    "registry spend failed for signer {idx}: HTTP {}",
                    resp.status()
                );
                let response = SpendResponse {
                    accepted: false,
                    reason: Some("registry update failed".to_string()),
                };
                return (StatusCode::OK, Json(response)).into_response();
            }
            Err(e) => {
                error!("registry spend request error for signer {idx}: {e}");
                let response = SpendResponse {
                    accepted: false,
                    reason: Some("registry update failed".to_string()),
                };
                return (StatusCode::OK, Json(response)).into_response();
            }
        }
    }

    let response = SpendResponse {
        accepted: true,
        reason: None,
    };

    (StatusCode::OK, Json(response)).into_response()
}

#[axum::debug_handler]
async fn mint_out_begin(
    State(state): State<AppState>,
    Json(req): Json<MintOutBeginRequest>,
) -> impl IntoResponse {
    let serial = req.serial;
    if req.payment_request.is_empty() {
        MINT_OUT_TOTAL.with_label_values(&["rejected"]).inc();
        let response = SpendResponse {
            accepted: false,
            reason: Some("empty payment_request".to_string()),
        };
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }
    let serial_hex = hex::encode(serial.0);

    let (signer_urls, client, lightning) = {
        let guard = state.coordinator.lock().await;
        (
            guard.signer_urls.clone(),
            guard.signer_client.clone(),
            guard.lightning.clone(),
        )
    };

    let issued_futures = signer_urls.iter().enumerate().map(|(idx, url)| {
        let client = client.clone();
        let serial = serial_hex.clone();
        let url = url.clone();
        async move {
            let full_url = format!("{url}/registry/issued/{serial}");
            let signer_id = format!("signer-{idx}");
            observe_signer_rpc(&signer_id, "registry_issued_check", async {
                client.get(&full_url).send().await
            })
            .await
        }
    });

    let issued_results = join_all(issued_futures).await;
    let mut issued_confirmations = 0usize;
    let total_signers = issued_results.len();

    for res in issued_results {
        match res {
            Ok(resp) if resp.status().is_success() => {
                issued_confirmations += 1;
            }
            Ok(_) => {}
            Err(e) => {
                error!("mint_out_begin issued registry check error: {e}");
                MINT_OUT_TOTAL.with_label_values(&["failed"]).inc();
                let response = SpendResponse {
                    accepted: false,
                    reason: Some("registry check failed".to_string()),
                };
                return (StatusCode::OK, Json(response)).into_response();
            }
        }
    }

    if issued_confirmations * 2 <= total_signers {
        MINT_OUT_TOTAL.with_label_values(&["rejected"]).inc();
        let response = SpendResponse {
            accepted: false,
            reason: Some("note not issued by majority".to_string()),
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    let spent_futures = signer_urls.iter().enumerate().map(|(idx, url)| {
        let client = client.clone();
        let serial = serial_hex.clone();
        let url = url.clone();
        async move {
            let full_url = format!("{url}/registry/spent/{serial}");
            let signer_id = format!("signer-{idx}");
            observe_signer_rpc(&signer_id, "registry_spent_check", async {
                client.get(&full_url).send().await
            })
            .await
        }
    });

    let spent_results = join_all(spent_futures).await;
    for res in spent_results {
        match res {
            Ok(resp) if resp.status().is_success() => {
                MINT_OUT_TOTAL.with_label_values(&["rejected"]).inc();
                let response = SpendResponse {
                    accepted: false,
                    reason: Some("note already spent".to_string()),
                };
                return (StatusCode::OK, Json(response)).into_response();
            }
            Ok(_) => {}
            Err(e) => {
                error!("mint_out_begin spent registry check error: {e}");
                MINT_OUT_TOTAL.with_label_values(&["failed"]).inc();
                let response = SpendResponse {
                    accepted: false,
                    reason: Some("registry check failed".to_string()),
                };
                return (StatusCode::OK, Json(response)).into_response();
            }
        }
    }

    let max_fee_msat = 0;
    let pay_start = std::time::Instant::now();
    let payment_result = lightning
        .pay_invoice(&req.payment_request, max_fee_msat)
        .await;
    let pay_elapsed = pay_start.elapsed().as_secs_f64();
    LIGHTNING_PAYMENT_LATENCY_SECONDS.observe(pay_elapsed);

    let payment = match payment_result {
        Ok(p) => p,
        Err(e) => {
            MINT_OUT_TOTAL.with_label_values(&["failed"]).inc();
            let response = SpendResponse {
                accepted: false,
                reason: Some(format!("payment failed: {e}")),
            };
            return (StatusCode::OK, Json(response)).into_response();
        }
    };

    let session = MintOutSession {
        serial,
        payment_hash: payment.payment_hash,
        amount_msat: 0,
        state: MintOutState::Succeeded,
    };

    {
        let mut guard = state.coordinator.lock().await;
        guard.mint_out_sessions.insert(serial, session);
    }

    let registry_req = RegistrySpendRequest {
        serial,
        challenge: Vec::new(),
        second_challenge: None,
        theta_u: None,
    };

    let futures = signer_urls.into_iter().map(|url| {
        let client = client.clone();
        let body = registry_req.clone();
        async move {
            let full_url = format!("{url}/registry/spend");
            client.post(&full_url).json(&body).send().await
        }
    });

    let results = join_all(futures).await;
    for (idx, res) in results.into_iter().enumerate() {
        match res {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => {
                error!(
                    "mint_out_begin registry spend failed for signer {idx}: HTTP {}",
                    resp.status()
                );
                MINT_OUT_TOTAL.with_label_values(&["failed"]).inc();
                let response = SpendResponse {
                    accepted: false,
                    reason: Some("registry update failed".to_string()),
                };
                return (StatusCode::OK, Json(response)).into_response();
            }
            Err(e) => {
                error!("mint_out_begin registry spend request error for signer {idx}: {e}");
                MINT_OUT_TOTAL.with_label_values(&["failed"]).inc();
                let response = SpendResponse {
                    accepted: false,
                    reason: Some("registry update failed".to_string()),
                };
                return (StatusCode::OK, Json(response)).into_response();
            }
        }
    }

    let response = SpendResponse {
        accepted: true,
        reason: None,
    };

    MINT_OUT_TOTAL.with_label_values(&["success"]).inc();

    (StatusCode::OK, Json(response)).into_response()
}

async fn run_session_cleanup(state: Arc<Mutex<CoordinatorState>>) {
    let interval = Duration::from_secs(60);
    loop {
        tokio::time::sleep(interval).await;

        let ttl_secs = {
            let guard = state.lock().await;
            guard.session_ttl_secs
        };

        if ttl_secs == 0 {
            continue;
        }

        let now = Instant::now();
        let mut expired_sessions = 0usize;
        let mut expired_mint_in = 0usize;

        {
            let mut guard = state.lock().await;

            guard.active_sessions.retain(|_, session| {
                let expired = now
                    .checked_duration_since(session.created_at)
                    .map(|d| d.as_secs() > ttl_secs)
                    .unwrap_or(false);
                if expired {
                    expired_sessions += 1;
                    false
                } else {
                    true
                }
            });

            guard.mint_in_sessions.retain(|_, session| {
                let expired = matches!(session.state, MintInState::Expired)
                    || now
                        .checked_duration_since(session.created_at)
                        .map(|d| d.as_secs() > ttl_secs)
                        .unwrap_or(false);
                if expired {
                    expired_mint_in += 1;
                    false
                } else {
                    true
                }
            });

            ACTIVE_SESSIONS_COUNT.set(guard.active_sessions.len() as f64);
        }

        if expired_sessions > 0 || expired_mint_in > 0 {
            tracing::debug!(
                "session cleanup expired_sessions={expired_sessions} expired_mint_in={expired_mint_in}"
            );
        }
    }
}

async fn run_settlement_persistence(
    state: Arc<Mutex<CoordinatorState>>,
    mut receiver: broadcast::Receiver<InvoiceSettledEvent>,
) {
    loop {
        match receiver.recv().await {
            Ok(event) => {
                let (pool, last_index_arc, session_id_opt) = {
                    let guard = state.lock().await;
                    let pool = guard.pool.clone();
                    let last_index_arc = guard.last_settle_index.clone();
                    let mut found_id = None;
                    for (id, s) in guard.mint_in_sessions.iter() {
                        if s.payment_hash == event.payment_hash {
                            found_id = Some(id.clone());
                            break;
                        }
                    }
                    (pool, last_index_arc, found_id)
                };

                {
                    let mut last = last_index_arc.lock().await;
                    if event.settle_index > *last {
                        *last = event.settle_index;
                    }
                }

                let idx = event.settle_index as i64;
                if let Err(e) = sqlx::query(
                    "INSERT INTO settle_index (id, idx) VALUES (1, ?1)
                     ON CONFLICT(id) DO UPDATE SET idx = excluded.idx",
                )
                .bind(idx)
                .execute(&pool)
                .await
                {
                    error!("failed to persist settle_index: {e}");
                }

                if let Some(session_id) = session_id_opt {
                    let state_clone = state.clone();
                    tokio::spawn(async move {
                        let _ = run_mint_in_signing(state_clone, session_id).await;
                    });
                }
            }
            Err(e) => {
                error!("settlement persistence receiver error: {e}");
            }
        }
    }
}

async fn run_anchor_loop(state: Arc<Mutex<CoordinatorState>>) {
    loop {
        let (
            interval_secs,
            interval_blocks,
            min_confirmations,
            fee_target_blocks,
            change_address,
            signer_url,
            signer_client,
            bitcoin_rpc_client,
            anchor_tracker,
        ) = {
            let guard = state.lock().await;
            (
                guard.anchor_interval_secs,
                guard.anchor_interval_blocks,
                guard.anchor_min_confirmations,
                guard.anchor_fee_target_blocks,
                guard.anchor_change_address.clone(),
                guard.signer_urls.first().cloned(),
                guard.signer_client.clone(),
                guard.bitcoin_rpc_client.clone(),
                guard.anchor_tracker.clone(),
            )
        };

        if interval_secs == 0 {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            continue;
        }

        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;

        let Some(signer_url) = signer_url else {
            continue;
        };

        let audit_url = format!("{signer_url}/audit");
        let resp = match signer_client.get(&audit_url).send().await {
            Ok(r) => r,
            Err(e) => {
                error!("anchor loop audit request error: {e}");
                continue;
            }
        };

        if !resp.status().is_success() {
            error!("anchor loop audit HTTP {}", resp.status());
            continue;
        }

        let body: AuditResponse = match resp.json().await {
            Ok(b) => b,
            Err(e) => {
                error!("anchor loop audit JSON error: {e}");
                continue;
            }
        };

        let issued_root_bytes = match hex::decode(body.issued_root) {
            Ok(b) if b.len() == 32 => b,
            Ok(_) => continue,
            Err(e) => {
                error!("anchor loop issued_root decode error: {e}");
                continue;
            }
        };

        let spent_root_bytes = match hex::decode(body.spent_root) {
            Ok(b) if b.len() == 32 => b,
            Ok(_) => continue,
            Err(e) => {
                error!("anchor loop spent_root decode error: {e}");
                continue;
            }
        };

        let mut issued_root = [0u8; 32];
        issued_root.copy_from_slice(&issued_root_bytes);
        let mut spent_root = [0u8; 32];
        spent_root.copy_from_slice(&spent_root_bytes);

        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(dur) => dur.as_secs(),
            Err(_) => 0,
        };
        let slot = if interval_secs > 0 {
            now / interval_secs
        } else {
            0
        };
        ANCHOR_SLOT.set(slot as f64);

        let commitment = MerkleCommitment {
            issued_root,
            spent_root,
            slot,
        };
        let commitment_hash_bytes = commitment_hash(&commitment);

        let payload = AnchorPayload {
            commitment_hash: commitment_hash_bytes,
            slot,
            version: 1,
        };

        let encoded = encode_anchor_payload(&payload);

        let mut txid = None;

        if let Some(rpc) = bitcoin_rpc_client {
            let current_height = match rpc.get_block_count().await {
                Ok(h) => h,
                Err(e) => {
                    error!("anchor loop get_block_count error: {e}");
                    continue;
                }
            };

            let network = env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "regtest".to_string());
            if network != "regtest" && current_height % (interval_blocks as u64) != 0 {
                continue;
            }

            let fee_rate = match rpc.estimate_smart_fee(fee_target_blocks).await {
                Ok(rate) => rate,
                Err(e) => {
                    error!("anchor loop estimate_smart_fee error: {e}");
                    continue;
                }
            };

            let utxos = match rpc.list_unspent(min_confirmations).await {
                Ok(u) => u,
                Err(e) => {
                    error!("anchor loop list_unspent error: {e}");
                    continue;
                }
            };

            if utxos.is_empty() {
                error!("insufficient UTXOs for anchoring");
                ANCHOR_SUBMIT_TOTAL.with_label_values(&["skipped"]).inc();
                continue;
            }

            // Simple coin selection: take the first one that is spendable
            let utxo = match utxos.iter().find(|u| u.spendable) {
                Some(u) => u,
                None => {
                    error!("no spendable UTXOs found");
                    ANCHOR_SUBMIT_TOTAL.with_label_values(&["skipped"]).inc();
                    continue;
                }
            };

            let change_addr = change_address.as_deref().unwrap_or("");
            if change_addr.is_empty() {
                error!("ANCHOR_CHANGE_ADDRESS not set");
                continue;
            }

            match AnchorTxBuilder::build_anchor_tx(utxo, &payload, fee_rate, change_addr) {
                Ok(tx_hex) => {
                    if fee_rate > 200.0 {
                        tracing::warn!("anchor fee rate too high: {} sat/vbyte", fee_rate);
                        ANCHOR_SUBMIT_TOTAL.with_label_values(&["skipped"]).inc();
                        continue;
                    }

                    match rpc.send_raw_transaction(&tx_hex).await {
                        Ok(id) => {
                            info!("anchor txid {id}");
                            ANCHOR_SUBMIT_TOTAL.with_label_values(&["success"]).inc();
                            txid = Some(id.clone());

                            let payload_hash = hex::encode(payload.commitment_hash);
                            if let Err(e) =
                                anchor_tracker.register_broadcast(&id, &payload_hash).await
                            {
                                error!("failed to register anchor broadcast: {e}");
                            }
                        }
                        Err(e) => {
                            error!("anchor loop send_raw_transaction error: {e}");
                            ANCHOR_SUBMIT_TOTAL.with_label_values(&["failed"]).inc();
                        }
                    }
                }
                Err(e) => {
                    error!("anchor loop build_anchor_tx error: {e}");
                    ANCHOR_SUBMIT_TOTAL.with_label_values(&["failed"]).inc();
                }
            }
        } else {
            info!(
                "anchor payload hex {} (no bitcoin rpc)",
                hex::encode(&encoded)
            );
            ANCHOR_SUBMIT_TOTAL.with_label_values(&["skipped"]).inc();
        }

        let record = AnchorRecord {
            payload,
            txid,
            anchored_at: SystemTime::now(),
        };

        {
            let mut guard = state.lock().await;
            guard.anchor_records.push(record);
            if guard.anchor_records.len() > 1000 {
                let excess = guard.anchor_records.len() - 1000;
                guard.anchor_records.drain(0..excess);
            }
        }
    }
}

async fn run_channel_balance_loop(state: Arc<Mutex<CoordinatorState>>) {
    loop {
        {
            let lightning = {
                let guard = state.lock().await;
                guard.lightning.clone()
            };
            if let Ok(balance) = lightning.get_channel_balance().await {
                CHANNEL_BALANCE_LOCAL_MSAT.set(balance.local_msat as f64);
                CHANNEL_BALANCE_REMOTE_MSAT.set(balance.remote_msat as f64);
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }
}

async fn audit(State(state): State<AppState>) -> impl IntoResponse {
    let (signer_urls, client, latest_anchor) = {
        let guard = state.coordinator.lock().await;
        (
            guard.signer_urls.clone(),
            guard.signer_client.clone(),
            guard.anchor_records.last().cloned(),
        )
    };

    let futures = signer_urls.into_iter().map(|url| {
        let client = client.clone();
        async move {
            let full_url = format!("{url}/audit");
            client.get(&full_url).send().await
        }
    });

    let results = join_all(futures).await;

    let mut issued_total = 0u64;
    let mut spent_total = 0u64;
    let mut outstanding_total = 0u64;
    let mut issued_root: Option<String> = None;
    let mut spent_root: Option<String> = None;

    for (idx, res) in results.into_iter().enumerate() {
        let resp = match res {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                error!("audit failed for signer {idx}: HTTP {}", r.status());
                return StatusCode::BAD_GATEWAY.into_response();
            }
            Err(e) => {
                error!("audit request error for signer {idx}: {e}");
                return StatusCode::BAD_GATEWAY.into_response();
            }
        };

        let body: AuditResponse = match resp.json().await {
            Ok(b) => b,
            Err(e) => {
                error!("audit JSON parse error for signer {idx}: {e}");
                return StatusCode::BAD_GATEWAY.into_response();
            }
        };

        if issued_total == 0 && idx == 0 {
            issued_total = body.issued_count;
        } else if issued_total != body.issued_count {
            tracing::warn!(
                "audit mismatch: issued_count {} vs {}",
                issued_total,
                body.issued_count
            );
            issued_total = std::cmp::max(issued_total, body.issued_count);
        }

        if spent_total == 0 && idx == 0 {
            spent_total = body.spent_count;
        } else if spent_total != body.spent_count {
            tracing::warn!(
                "audit mismatch: spent_count {} vs {}",
                spent_total,
                body.spent_count
            );
            spent_total = std::cmp::max(spent_total, body.spent_count);
        }

        if outstanding_total == 0 && idx == 0 {
            outstanding_total = body.outstanding;
        } else if outstanding_total != body.outstanding {
            tracing::warn!(
                "audit mismatch: outstanding {} vs {}",
                outstanding_total,
                body.outstanding
            );
            outstanding_total = std::cmp::max(outstanding_total, body.outstanding);
        }

        if issued_root.is_none() {
            issued_root = Some(body.issued_root);
        }
        if spent_root.is_none() {
            spent_root = Some(body.spent_root);
        }
    }

    let (anchor_hash, anchor_slot) = if let Some(rec) = latest_anchor {
        (
            Some(hex::encode(rec.payload.commitment_hash)),
            Some(rec.payload.slot),
        )
    } else {
        (None, None)
    };

    let response = AuditResponse {
        issued_count: issued_total,
        spent_count: spent_total,
        outstanding: outstanding_total,
        issued_root: issued_root.unwrap_or_else(|| "0".to_string()),
        spent_root: spent_root.unwrap_or_else(|| "0".to_string()),
        anchored_at: None,
        anchor_hash,
        anchor_slot,
    };

    (StatusCode::OK, Json(response)).into_response()
}

async fn anchors(State(state): State<AppState>) -> impl IntoResponse {
    let records = {
        let guard = state.coordinator.lock().await;
        let len = guard.anchor_records.len();
        let start = len.saturating_sub(100);
        guard.anchor_records[start..].to_vec()
    };

    (StatusCode::OK, Json(records)).into_response()
}

async fn health() -> impl IntoResponse {
    StatusCode::OK
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

async fn require_gateway_cn(
    State(state): State<AppState>,
    req: Request,
    next: middleware::Next,
) -> impl IntoResponse {
    let client_cn = req
        .extensions()
        .get::<ClientCertCn>()
        .map(|wrapper| wrapper.0.clone());
    let expected = state.gateway_cn.as_str();
    if client_cn.as_deref() != Some(expected) {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(req).await
}

async fn require_operator_secret(
    State(state): State<AppState>,
    req: Request,
    next: middleware::Next,
) -> impl IntoResponse {
    let expected = state.operator_secret.as_str();
    let header_val = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if let Some(h) = header_val {
        if let Some(token) = h.strip_prefix("Bearer ") {
            if token == expected {
                return next.run(req).await;
            }
        }
    }
    StatusCode::UNAUTHORIZED.into_response()
}

fn hash_message(message: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize().to_vec()
}

fn to_array32(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Some(arr)
}
