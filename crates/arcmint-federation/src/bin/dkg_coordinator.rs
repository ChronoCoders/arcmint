use arcmint_core::dkg::state::{CeremonyPhase, CeremonyState};
use arcmint_core::dkg::transcript::{compute_transcript_hash, TranscriptEntry, TranscriptEvent};
use arcmint_core::dkg::types::{
    CeremonyConfig, DkgOutput, ParticipantId, Round1Package, Round2Package,
};
use arcmint_core::tls::load_tls_server_config;
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Json;
use hex::encode as hex_encode;
use hyper::body::Incoming;
use hyper::Request as HyperRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Clone)]
struct DkgCoordinatorState {
    ceremony: Option<CeremonyState>,
    operator_tokens: HashMap<ParticipantId, String>,
}

#[derive(Clone)]
struct AppState {
    state: Arc<Mutex<DkgCoordinatorState>>,
}

#[derive(Clone)]
struct OperatorId(ParticipantId);

#[derive(Deserialize)]
struct AbortRequest {
    reason: Option<String>,
}

#[derive(Serialize)]
struct CreateResponse {
    ceremony_id: String,
}

#[derive(Serialize)]
struct JoinResponse {
    phase: CeremonyPhase,
    ceremony_id: String,
}

#[derive(Serialize)]
struct Round1Response {
    all_packages: Vec<Round1Package>,
}

#[derive(Serialize)]
struct StatusResponse {
    phase: CeremonyPhase,
    joined_count: usize,
    round1_count: usize,
    round2_count: usize,
    output_count: usize,
    transcript_hash: Option<String>,
}

#[derive(Serialize)]
struct OutputResponse {
    status: String,
    transcript_hash: Option<String>,
}

#[derive(Serialize)]
struct AbortResponse {
    transcript_hash: String,
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tracing_subscriber::fmt().init();

    let port: u16 = env::var("DKG_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7100);

    let tokens_env =
        env::var("DKG_OPERATOR_TOKENS").expect("DKG_OPERATOR_TOKENS env var must be set");
    let raw_tokens: HashMap<String, String> =
        serde_json::from_str(&tokens_env).expect("invalid DKG_OPERATOR_TOKENS JSON");
    let mut operator_tokens = HashMap::new();
    for (id, token) in raw_tokens {
        operator_tokens.insert(ParticipantId(id), token);
    }

    let state = DkgCoordinatorState {
        ceremony: None,
        operator_tokens,
    };

    let shared_state = AppState {
        state: Arc::new(Mutex::new(state)),
    };

    let timeout_state = shared_state.clone();
    tokio::spawn(async move { run_timeout_loop(timeout_state).await });

    let auth_layer = middleware::from_fn_with_state(shared_state.clone(), require_operator);

    let app = axum::Router::new()
        .route(
            "/ceremony/create",
            post(ceremony_create).route_layer(auth_layer.clone()),
        )
        .route(
            "/ceremony/join",
            post(ceremony_join).route_layer(auth_layer.clone()),
        )
        .route(
            "/ceremony/round1",
            post(ceremony_round1).route_layer(auth_layer.clone()),
        )
        .route(
            "/ceremony/round1/packages",
            get(ceremony_round1_packages).route_layer(auth_layer.clone()),
        )
        .route(
            "/ceremony/round2",
            post(ceremony_round2).route_layer(auth_layer.clone()),
        )
        .route(
            "/ceremony/round2/packages",
            get(ceremony_round2_packages).route_layer(auth_layer.clone()),
        )
        .route(
            "/ceremony/output",
            post(ceremony_output).route_layer(auth_layer.clone()),
        )
        .route(
            "/ceremony/status",
            get(ceremony_status).route_layer(auth_layer.clone()),
        )
        .route(
            "/ceremony/transcript",
            get(ceremony_transcript).route_layer(auth_layer.clone()),
        )
        .route(
            "/ceremony/abort",
            post(ceremony_abort).route_layer(auth_layer),
        )
        .route("/health", get(health))
        .with_state(shared_state.clone());

    let tls_cert = env::var("DKG_TLS_CERT").expect("DKG_TLS_CERT env var must be set for DKG TLS");
    let tls_key = env::var("DKG_TLS_KEY").expect("DKG_TLS_KEY env var must be set for DKG TLS");
    let tls_ca = env::var("DKG_CA_FILE").expect("DKG_CA_FILE env var must be set for DKG mTLS");

    let tls_config = load_tls_server_config(
        FsPath::new(&tls_cert),
        FsPath::new(&tls_key),
        Some(FsPath::new(&tls_ca)),
    )
    .expect("failed to build DKG TLS server config");
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("starting DKG coordinator on {addr} (mTLS enabled)");

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
                error!("error while serving DKG connection from {peer_addr}: {err}");
            }
        });
    }
}

async fn require_operator(
    State(state): State<AppState>,
    mut req: Request,
    next: middleware::Next,
) -> impl IntoResponse {
    let token = match req
        .headers()
        .get("X-Operator-Token")
        .and_then(|h| h.to_str().ok())
    {
        Some(t) => t,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let participant = {
        let guard = state.state.lock().await;
        guard
            .operator_tokens
            .iter()
            .find_map(|(id, t)| if t == token { Some(id.clone()) } else { None })
    };

    let Some(participant_id) = participant else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    req.extensions_mut().insert(OperatorId(participant_id));
    next.run(req).await
}

async fn ceremony_create(
    State(state): State<AppState>,
    Json(mut config): Json<CeremonyConfig>,
) -> impl IntoResponse {
    if let Err(e) = config.validate() {
        return (StatusCode::BAD_REQUEST, Json(Value::String(e.to_string()))).into_response();
    }

    let ceremony_id = Uuid::new_v4().to_string();
    config.ceremony_id = ceremony_id.clone();

    let mut guard = state.state.lock().await;
    if guard.ceremony.is_some() {
        return StatusCode::CONFLICT.into_response();
    }

    let mut ceremony = CeremonyState {
        config,
        phase: CeremonyPhase::WaitingForParticipants,
        joined: HashMap::new(),
        round1_packages: HashMap::new(),
        round2_packages: HashMap::new(),
        outputs: HashMap::new(),
        transcript: Vec::new(),
    };

    let entry = TranscriptEntry {
        timestamp: now_ts(),
        event: TranscriptEvent::CeremonyStarted {
            config: ceremony.config.clone(),
        },
    };
    ceremony.transcript.push(entry);
    guard.ceremony = Some(ceremony);

    (StatusCode::OK, Json(CreateResponse { ceremony_id })).into_response()
}

async fn ceremony_join(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorId>,
) -> impl IntoResponse {
    let mut guard = state.state.lock().await;
    let Some(ceremony) = guard.ceremony.as_mut() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match ceremony.phase {
        CeremonyPhase::WaitingForParticipants => {}
        _ => return StatusCode::BAD_REQUEST.into_response(),
    }

    let participant = operator.0;
    ceremony.joined.insert(participant.clone(), true);

    let entry = TranscriptEntry {
        timestamp: now_ts(),
        event: TranscriptEvent::ParticipantJoined {
            id: participant.clone(),
        },
    };
    ceremony.transcript.push(entry);

    if ceremony.all_joined() {
        ceremony.phase = CeremonyPhase::Round1 {
            started_at: now_ts(),
        };
    }

    let phase = ceremony.phase.clone();
    let ceremony_id = ceremony.config.ceremony_id.clone();

    (StatusCode::OK, Json(JoinResponse { phase, ceremony_id })).into_response()
}

async fn ceremony_round1(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorId>,
    Json(pkg): Json<Round1Package>,
) -> impl IntoResponse {
    let mut guard = state.state.lock().await;
    let Some(ceremony) = guard.ceremony.as_mut() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let threshold = ceremony.config.threshold as usize;

    match ceremony.phase {
        CeremonyPhase::Round1 { .. } => {}
        _ => return StatusCode::BAD_REQUEST.into_response(),
    }

    if pkg.participant_id != operator.0 {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    if ceremony.round1_packages.contains_key(&pkg.participant_id) {
        return StatusCode::CONFLICT.into_response();
    }

    if pkg.commitment.len() != threshold {
        return StatusCode::BAD_REQUEST.into_response();
    }

    if pkg.proof_of_knowledge.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let mut hasher = Sha256::new();
    for c in &pkg.commitment {
        hasher.update(c);
    }
    let commitment_hash = hex_encode(hasher.finalize());

    let entry = TranscriptEntry {
        timestamp: now_ts(),
        event: TranscriptEvent::Round1Submitted {
            participant: pkg.participant_id.clone(),
            commitment_hash,
        },
    };
    ceremony.transcript.push(entry);

    ceremony
        .round1_packages
        .insert(pkg.participant_id.clone(), pkg);

    if ceremony.all_round1_complete() {
        ceremony.phase = CeremonyPhase::Round2 {
            started_at: now_ts(),
        };
    }

    let all_packages = ceremony
        .round1_packages
        .values()
        .cloned()
        .collect::<Vec<_>>();

    (StatusCode::OK, Json(Round1Response { all_packages })).into_response()
}

async fn ceremony_round1_packages(
    State(state): State<AppState>,
    Extension(_operator): Extension<OperatorId>,
) -> impl IntoResponse {
    let guard = state.state.lock().await;
    let Some(ceremony) = guard.ceremony.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match ceremony.phase {
        CeremonyPhase::Round1 { .. } | CeremonyPhase::Round2 { .. } => {}
        _ => return StatusCode::BAD_REQUEST.into_response(),
    }

    let all_packages = ceremony
        .round1_packages
        .values()
        .cloned()
        .collect::<Vec<_>>();

    (StatusCode::OK, Json(Round1Response { all_packages })).into_response()
}

async fn ceremony_round2(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorId>,
    Json(packages): Json<Vec<Round2Package>>,
) -> impl IntoResponse {
    let mut guard = state.state.lock().await;
    let Some(ceremony) = guard.ceremony.as_mut() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match ceremony.phase {
        CeremonyPhase::Round2 { .. } => {}
        _ => return StatusCode::BAD_REQUEST.into_response(),
    }

    let from_id = operator.0;

    if packages.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    for pkg in &packages {
        if pkg.from != from_id {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    let expected: Vec<_> = ceremony
        .config
        .participants
        .iter()
        .filter(|id| **id != from_id)
        .cloned()
        .collect();

    let mut seen = HashMap::new();
    for pkg in &packages {
        seen.insert(pkg.to.clone(), true);
    }

    if expected.len() != seen.len() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    for id in expected {
        if !seen.contains_key(&id) {
            return StatusCode::BAD_REQUEST.into_response();
        }
    }

    for pkg in &packages {
        let entry = TranscriptEntry {
            timestamp: now_ts(),
            event: TranscriptEvent::Round2Submitted {
                from: pkg.from.clone(),
                to: pkg.to.clone(),
            },
        };
        ceremony.transcript.push(entry);
    }

    ceremony.round2_packages.insert(from_id, packages);

    (StatusCode::OK, Json(Value::String("accepted".to_string()))).into_response()
}

async fn ceremony_round2_packages(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorId>,
) -> impl IntoResponse {
    let guard = state.state.lock().await;
    let Some(ceremony) = guard.ceremony.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let to_id = operator.0;
    let mut result = Vec::new();
    for pkgs in ceremony.round2_packages.values() {
        for pkg in pkgs {
            if pkg.to == to_id {
                result.push(pkg.clone());
            }
        }
    }

    (StatusCode::OK, Json(result)).into_response()
}

async fn ceremony_output(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorId>,
    Json(output): Json<DkgOutput>,
) -> impl IntoResponse {
    let mut guard = state.state.lock().await;
    let Some(ceremony) = guard.ceremony.as_mut() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match ceremony.phase {
        CeremonyPhase::Round2 { .. } | CeremonyPhase::Finalizing => {}
        _ => return StatusCode::BAD_REQUEST.into_response(),
    }

    if output.participant_id != operator.0 {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    if serde_json::from_slice::<Value>(&output.public_key_package).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let mut hasher = Sha256::new();
    hasher.update(&output.public_key_package);
    let public_key_hash = hex_encode(hasher.finalize());

    let entry = TranscriptEntry {
        timestamp: now_ts(),
        event: TranscriptEvent::OutputIssued {
            participant: output.participant_id.clone(),
            public_key_hash: public_key_hash.clone(),
        },
    };
    ceremony.transcript.push(entry);

    ceremony
        .outputs
        .insert(output.participant_id.clone(), output);

    let participant_count = ceremony.config.participants.len();

    if ceremony.outputs.len() < participant_count {
        return (
            StatusCode::OK,
            Json(OutputResponse {
                status: "accepted".to_string(),
                transcript_hash: None,
            }),
        )
            .into_response();
    }

    ceremony.phase = CeremonyPhase::Finalizing;

    let mut iter = ceremony.outputs.values();
    let first = iter
        .next()
        .map(|o| o.public_key_package.clone())
        .unwrap_or_default();

    let mut all_match = true;
    for o in iter {
        if o.public_key_package != first {
            all_match = false;
            break;
        }
    }

    if !all_match {
        let reason = "public key package mismatch".to_string();
        ceremony.phase = CeremonyPhase::Aborted {
            reason: reason.clone(),
        };
        let entry = TranscriptEntry {
            timestamp: now_ts(),
            event: TranscriptEvent::CeremonyAborted { reason },
        };
        ceremony.transcript.push(entry);
        let hash = compute_transcript_hash(&ceremony.transcript);
        let transcript_hash = hex_encode(hash);
        return (
            StatusCode::OK,
            Json(OutputResponse {
                status: "accepted".to_string(),
                transcript_hash: Some(transcript_hash),
            }),
        )
            .into_response();
    }

    let entry = TranscriptEntry {
        timestamp: now_ts(),
        event: TranscriptEvent::CeremonyCompleted {
            public_key_hash: public_key_hash.clone(),
        },
    };
    ceremony.transcript.push(entry);
    ceremony.phase = CeremonyPhase::Complete;

    let hash = compute_transcript_hash(&ceremony.transcript);
    let transcript_hash = hex_encode(hash);

    (
        StatusCode::OK,
        Json(OutputResponse {
            status: "complete".to_string(),
            transcript_hash: Some(transcript_hash),
        }),
    )
        .into_response()
}

async fn ceremony_status(
    State(state): State<AppState>,
    Extension(_operator): Extension<OperatorId>,
) -> impl IntoResponse {
    let guard = state.state.lock().await;
    let Some(ceremony) = guard.ceremony.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let joined_count = ceremony.joined.values().filter(|v| **v).count();
    let round1_count = ceremony.round1_packages.len();
    let round2_count = ceremony.round2_packages.len();
    let output_count = ceremony.outputs.len();

    let transcript_hash = if ceremony.transcript.is_empty() {
        None
    } else {
        let hash = compute_transcript_hash(&ceremony.transcript);
        Some(hex_encode(hash))
    };

    (
        StatusCode::OK,
        Json(StatusResponse {
            phase: ceremony.phase.clone(),
            joined_count,
            round1_count,
            round2_count,
            output_count,
            transcript_hash,
        }),
    )
        .into_response()
}

async fn ceremony_transcript(
    State(state): State<AppState>,
    Extension(_operator): Extension<OperatorId>,
) -> impl IntoResponse {
    let guard = state.state.lock().await;
    let Some(ceremony) = guard.ceremony.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    (StatusCode::OK, Json(ceremony.transcript.clone())).into_response()
}

async fn ceremony_abort(
    State(state): State<AppState>,
    Json(req): Json<AbortRequest>,
) -> impl IntoResponse {
    let mut guard = state.state.lock().await;
    let Some(ceremony) = guard.ceremony.as_mut() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let reason = req
        .reason
        .unwrap_or_else(|| "aborted by operator".to_string());
    ceremony.phase = CeremonyPhase::Aborted {
        reason: reason.clone(),
    };
    let entry = TranscriptEntry {
        timestamp: now_ts(),
        event: TranscriptEvent::CeremonyAborted { reason },
    };
    ceremony.transcript.push(entry);

    let hash = compute_transcript_hash(&ceremony.transcript);
    let transcript_hash = hex_encode(hash);

    (StatusCode::OK, Json(AbortResponse { transcript_hash })).into_response()
}

async fn run_timeout_loop(state: AppState) {
    let interval = Duration::from_secs(30);
    loop {
        tokio::time::sleep(interval).await;

        let mut guard = state.state.lock().await;
        let Some(ceremony) = guard.ceremony.as_mut() else {
            continue;
        };

        let now = now_ts();
        let timeout = ceremony.config.round_timeout_secs;

        match ceremony.phase {
            CeremonyPhase::Round1 { started_at } => {
                if now.saturating_sub(started_at) > timeout {
                    let reason = "Round 1 timeout".to_string();
                    ceremony.phase = CeremonyPhase::Aborted {
                        reason: reason.clone(),
                    };
                    let entry = TranscriptEntry {
                        timestamp: now,
                        event: TranscriptEvent::CeremonyAborted { reason },
                    };
                    ceremony.transcript.push(entry);
                    error!("DKG round 1 timeout, ceremony aborted");
                }
            }
            CeremonyPhase::Round2 { started_at } => {
                if now.saturating_sub(started_at) > timeout {
                    let reason = "Round 2 timeout".to_string();
                    ceremony.phase = CeremonyPhase::Aborted {
                        reason: reason.clone(),
                    };
                    let entry = TranscriptEntry {
                        timestamp: now,
                        event: TranscriptEvent::CeremonyAborted { reason },
                    };
                    ceremony.transcript.push(entry);
                    error!("DKG round 2 timeout, ceremony aborted");
                }
            }
            _ => {}
        }
    }
}

async fn health() -> impl IntoResponse {
    StatusCode::OK
}
