use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, Wrap},
    Terminal,
};
use serde::Deserialize;
use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

// ── Configuration ──────────────────────────────────────────────────────────────

struct Config {
    bitcoin_rpc_url: String,
    bitcoin_rpc_user: String,
    bitcoin_rpc_pass: String,
    coordinator_url: String,
    gateway_url: String,
    merchant_url: String,
    signer_urls: Vec<String>,
    operator_secret: String,
    refresh_secs: u64,
}

impl Config {
    fn from_env() -> Self {
        Config {
            bitcoin_rpc_url: std::env::var("BITCOIN_RPC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8332".to_string()),
            bitcoin_rpc_user: std::env::var("BITCOIN_RPC_USER")
                .unwrap_or_else(|_| "arcmint".to_string()),
            bitcoin_rpc_pass: std::env::var("BITCOIN_RPC_PASS")
                .unwrap_or_default(),
            coordinator_url: std::env::var("COORDINATOR_URL")
                .unwrap_or_else(|_| "https://127.0.0.1:7000".to_string()),
            gateway_url: std::env::var("GATEWAY_URL")
                .unwrap_or_else(|_| "https://127.0.0.1:7004".to_string()),
            merchant_url: std::env::var("MERCHANT_URL")
                .unwrap_or_else(|_| "https://127.0.0.1:7005".to_string()),
            signer_urls: std::env::var("SIGNER_URLS")
                .unwrap_or_else(|_| {
                    "https://127.0.0.1:7001,https://127.0.0.1:7002,https://127.0.0.1:7003"
                        .to_string()
                })
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            operator_secret: std::env::var("OPERATOR_SECRET").unwrap_or_default(),
            refresh_secs: std::env::var("MONITOR_REFRESH_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
        }
    }
}

// ── Data model ─────────────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct BitcoinState {
    chain: String,
    blocks: u64,
    headers: u64,
    progress: f64,
    pruned: bool,
    prune_height: u64,
    size_gb: f64,
    peers: u64,
    mempool_txs: u64,
    mempool_mb: f64,
    last_block_time: String,
    error: Option<String>,
}

#[derive(Default, Clone)]
struct ServiceState {
    name: String,
    healthy: bool,
    latency_ms: u64,
    error: Option<String>,
}

#[derive(Default, Clone)]
struct AnchorState {
    issued_count: u64,
    spent_count: u64,
    outstanding: u64,
    issued_root: String,
    spent_root: String,
    last_anchor_hash: Option<String>,
    last_anchor_slot: Option<u64>,
    error: Option<String>,
}

#[derive(Default, Clone)]
struct AppState {
    bitcoin: BitcoinState,
    services: Vec<ServiceState>,
    anchor: AnchorState,
    last_refresh: Option<Instant>,
    refreshing: bool,
    log: Vec<String>,
}

// ── JSON types for RPC ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    message: String,
}

#[derive(Deserialize)]
struct BlockchainInfo {
    chain: String,
    blocks: u64,
    headers: u64,
    verificationprogress: f64,
    pruned: bool,
    #[serde(default)]
    pruneheight: u64,
    size_on_disk: u64,
    #[serde(default)]
    time: u64,
}

#[derive(Deserialize)]
struct PeerEntry {
    #[allow(dead_code)]
    id: u64,
}

#[derive(Deserialize)]
struct MempoolInfo {
    size: u64,
    usage: u64,
}

#[derive(Deserialize)]
struct AuditResponse {
    issued_count: u64,
    spent_count: u64,
    outstanding: u64,
    issued_root: String,
    spent_root: String,
    anchor_hash: Option<String>,
    anchor_slot: Option<u64>,
}

// ── Fetchers ───────────────────────────────────────────────────────────────────

async fn fetch_bitcoin(cfg: &Config, client: &reqwest::Client) -> BitcoinState {
    let mut state = BitcoinState::default();

    let rpc = |method: &str, params: serde_json::Value| {
        client
            .post(&cfg.bitcoin_rpc_url)
            .basic_auth(&cfg.bitcoin_rpc_user, Some(&cfg.bitcoin_rpc_pass))
            .json(&serde_json::json!({
                "jsonrpc": "1.0",
                "id": method,
                "method": method,
                "params": params,
            }))
    };

    // getblockchaininfo
    match rpc("getblockchaininfo", serde_json::json!([]))
        .send()
        .await
    {
        Ok(resp) => match resp.json::<RpcResponse<BlockchainInfo>>().await {
            Ok(r) => {
                if let Some(e) = r.error {
                    state.error = Some(e.message);
                    return state;
                }
                if let Some(info) = r.result {
                    state.chain = info.chain;
                    state.blocks = info.blocks;
                    state.headers = info.headers;
                    state.progress = info.verificationprogress * 100.0;
                    state.pruned = info.pruned;
                    state.prune_height = info.pruneheight;
                    state.size_gb = info.size_on_disk as f64 / 1e9;
                    if info.time > 0 {
                        let dt = chrono::DateTime::from_timestamp(info.time as i64, 0)
                            .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
                            .unwrap_or_default();
                        state.last_block_time = dt;
                    }
                }
            }
            Err(e) => {
                state.error = Some(format!("parse error: {e}"));
                return state;
            }
        },
        Err(e) => {
            state.error = Some(format!("connection error: {e}"));
            return state;
        }
    }

    // getpeerinfo
    if let Ok(resp) = rpc("getpeerinfo", serde_json::json!([])).send().await {
        if let Ok(r) = resp.json::<RpcResponse<Vec<PeerEntry>>>().await {
            if let Some(peers) = r.result {
                state.peers = peers.len() as u64;
            }
        }
    }

    // getmempoolinfo
    if let Ok(resp) = rpc("getmempoolinfo", serde_json::json!([])).send().await {
        if let Ok(r) = resp.json::<RpcResponse<MempoolInfo>>().await {
            if let Some(info) = r.result {
                state.mempool_txs = info.size;
                state.mempool_mb = info.usage as f64 / 1e6;
            }
        }
    }

    state
}

async fn fetch_service(client: &reqwest::Client, name: &str, url: &str) -> ServiceState {
    let health_url = format!("{url}/health");
    let start = Instant::now();
    match client
        .get(&health_url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => ServiceState {
            name: name.to_string(),
            healthy: resp.status().is_success(),
            latency_ms: start.elapsed().as_millis() as u64,
            error: None,
        },
        Err(e) => ServiceState {
            name: name.to_string(),
            healthy: false,
            latency_ms: start.elapsed().as_millis() as u64,
            error: Some(e.to_string()),
        },
    }
}

async fn fetch_audit(
    cfg: &Config,
    client: &reqwest::Client,
) -> AnchorState {
    let url = format!("{}/audit", cfg.coordinator_url);
    match client
        .get(&url)
        .header(
            "Authorization",
            format!("Bearer {}", cfg.operator_secret),
        )
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => match resp.json::<AuditResponse>().await {
            Ok(a) => AnchorState {
                issued_count: a.issued_count,
                spent_count: a.spent_count,
                outstanding: a.outstanding,
                issued_root: a.issued_root,
                spent_root: a.spent_root,
                last_anchor_hash: a.anchor_hash,
                last_anchor_slot: a.anchor_slot,
                error: None,
            },
            Err(e) => AnchorState {
                error: Some(format!("parse: {e}")),
                ..Default::default()
            },
        },
        Err(e) => AnchorState {
            error: Some(format!("connection: {e}")),
            ..Default::default()
        },
    }
}

async fn refresh(cfg: &Config, client: &reqwest::Client) -> (BitcoinState, Vec<ServiceState>, AnchorState) {
    let bitcoin = fetch_bitcoin(cfg, client).await;

    let mut services = Vec::new();
    services.push(fetch_service(client, "coordinator", &cfg.coordinator_url).await);
    services.push(fetch_service(client, "gateway", &cfg.gateway_url).await);
    services.push(fetch_service(client, "merchant", &cfg.merchant_url).await);
    for (i, url) in cfg.signer_urls.iter().enumerate() {
        services.push(fetch_service(client, &format!("signer-{}", i + 1), url).await);
    }

    let anchor = fetch_audit(cfg, client).await;

    (bitcoin, services, anchor)
}

// ── UI rendering ───────────────────────────────────────────────────────────────

fn render(frame: &mut ratatui::Frame, state: &AppState) {
    let area = frame.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // title bar
            Constraint::Min(0),     // main content
            Constraint::Length(1),  // status bar
        ])
        .split(area);

    // Title bar
    let title_text = if state.refreshing {
        " ArcMint Monitor  [refreshing…]"
    } else {
        let ago = state
            .last_refresh
            .map(|t| {
                let s = t.elapsed().as_secs();
                if s < 60 { format!(" ({}s ago)", s) } else { format!(" ({}m ago)", s / 60) }
            })
            .unwrap_or_default();
        &*Box::leak(format!(" ArcMint Monitor  last refresh{ago}").into_boxed_str())
    };
    frame.render_widget(
        Paragraph::new(title_text).style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        outer[0],
    );

    // Main content: left | right
    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(outer[1]);

    // Left column: bitcoin + services
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(14), Constraint::Min(0)])
        .split(main[0]);

    render_bitcoin(frame, &state.bitcoin, left[0]);
    render_services(frame, &state.services, left[1]);

    // Right column: anchor + log
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(12), Constraint::Min(0)])
        .split(main[1]);

    render_anchor(frame, &state.anchor, right[0]);
    render_log(frame, &state.log, right[1]);

    // Status bar
    frame.render_widget(
        Paragraph::new("  q: quit   r: refresh now").style(
            Style::default().fg(Color::DarkGray),
        ),
        outer[2],
    );
}

fn render_bitcoin(frame: &mut ratatui::Frame, btc: &BitcoinState, area: Rect) {
    let block = Block::default()
        .title(" Bitcoin Core ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    if let Some(err) = &btc.error {
        frame.render_widget(
            Paragraph::new(format!("ERROR: {err}"))
                .style(Style::default().fg(Color::Red))
                .block(block),
            area,
        );
        return;
    }

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let sync_color = if btc.progress >= 99.99 { Color::Green } else { Color::Yellow };

    // Sync progress bar
    let gauge_area = Rect { x: inner.x, y: inner.y, width: inner.width, height: 1 };
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(sync_color))
        .ratio((btc.progress / 100.0).clamp(0.0, 1.0))
        .label(format!("{:.4}%", btc.progress));
    frame.render_widget(gauge, gauge_area);

    let rows = vec![
        row2("Chain", btc.chain.clone()),
        row2("Height", format!("{} / {} headers", btc.blocks, btc.headers)),
        row2("Last block", btc.last_block_time.clone()),
        row2("Peers", btc.peers.to_string()),
        row2("Mempool", format!("{} txs  ({:.1} MB)", btc.mempool_txs, btc.mempool_mb)),
        row2("Pruned", if btc.pruned { format!("yes  (prune height {})", btc.prune_height) } else { "no".to_string() }),
        row2("Disk", format!("{:.3} GB", btc.size_gb)),
    ];

    let table = Table::new(
        rows,
        [Constraint::Length(12), Constraint::Min(0)],
    );
    let table_area = Rect {
        x: inner.x,
        y: inner.y + 1,
        width: inner.width,
        height: inner.height.saturating_sub(1),
    };
    frame.render_widget(table, table_area);
}

fn render_services(frame: &mut ratatui::Frame, services: &[ServiceState], area: Rect) {
    let block = Block::default()
        .title(" Services ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows: Vec<Row> = services
        .iter()
        .map(|s| {
            let status = if s.healthy {
                Span::styled("● UP  ", Style::default().fg(Color::Green))
            } else {
                Span::styled("● DOWN", Style::default().fg(Color::Red))
            };
            let latency = Span::styled(
                format!("{:>4}ms", s.latency_ms),
                Style::default().fg(Color::DarkGray),
            );
            let name = Span::raw(format!("{:<12}", s.name));
            let detail = s
                .error
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(30)
                .collect::<String>();
            Row::new(vec![
                Cell::from(status),
                Cell::from(name),
                Cell::from(latency),
                Cell::from(Span::styled(detail, Style::default().fg(Color::DarkGray))),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(13),
            Constraint::Length(7),
            Constraint::Min(0),
        ],
    )
    .header(
        Row::new(vec!["Status", "Service", "Latency", ""])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    );

    frame.render_widget(table, inner);
}

fn render_anchor(frame: &mut ratatui::Frame, anchor: &AnchorState, area: Rect) {
    let block = Block::default()
        .title(" Anchoring & Registry ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    if let Some(err) = &anchor.error {
        frame.render_widget(
            Paragraph::new(format!("ERROR: {err}"))
                .style(Style::default().fg(Color::Red))
                .block(block),
            area,
        );
        return;
    }

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let last_anchor = anchor
        .last_anchor_hash
        .as_deref()
        .map(|h| format!("{}…", &h[..h.len().min(16)]))
        .unwrap_or_else(|| "none yet".to_string());
    let slot = anchor
        .last_anchor_slot
        .map(|s| s.to_string())
        .unwrap_or_else(|| "—".to_string());

    let rows = vec![
        row2("Issued", anchor.issued_count.to_string()),
        row2("Spent", anchor.spent_count.to_string()),
        row2("Outstanding", anchor.outstanding.to_string()),
        row2("Last anchor", last_anchor),
        row2("Anchor slot", slot),
        row2(
            "Issued root",
            format!("{}…", anchor.issued_root.chars().take(16).collect::<String>()),
        ),
        row2(
            "Spent root",
            format!("{}…", anchor.spent_root.chars().take(16).collect::<String>()),
        ),
    ];

    let table = Table::new(rows, [Constraint::Length(13), Constraint::Min(0)]);
    frame.render_widget(table, inner);
}

fn render_log(frame: &mut ratatui::Frame, log: &[String], area: Rect) {
    let block = Block::default()
        .title(" Events ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let inner_height = block.inner(area).height as usize;
    let lines: Vec<Line> = log
        .iter()
        .rev()
        .take(inner_height)
        .rev()
        .map(|l| Line::from(Span::styled(l.clone(), Style::default().fg(Color::DarkGray))))
        .collect();

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn row2(label: &str, value: String) -> Row<'static> {
    Row::new(vec![
        Cell::from(Span::styled(
            format!("{label:<13}"),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::raw(value)),
    ])
}

// ── Main ───────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env if present
    if let Ok(content) = std::fs::read_to_string(".env") {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                if std::env::var(k).is_err() {
                    std::env::set_var(k, v);
                }
            }
        }
    }

    let cfg = Config::from_env();

    let http_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // self-signed federation certs
        .timeout(Duration::from_secs(10))
        .build()?;

    let state = Arc::new(Mutex::new(AppState::default()));

    // Initial refresh in background
    {
        let cfg_ref = &cfg;
        let client_ref = &http_client;
        let (btc, svcs, anc) = refresh(cfg_ref, client_ref).await;
        let mut s = state.lock().await;
        s.bitcoin = btc;
        s.services = svcs;
        s.anchor = anc;
        s.last_refresh = Some(Instant::now());
        s.log.push(format!(
            "{} startup refresh complete",
            chrono::Utc::now().format("%H:%M:%S")
        ));
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let refresh_interval = Duration::from_secs(cfg.refresh_secs);
    let mut last_auto_refresh = Instant::now();

    loop {
        {
            let s = state.lock().await;
            terminal.draw(|frame| render(frame, &s))?;
        }

        // Poll for input with short timeout
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => break,
                        KeyCode::Char('r') | KeyCode::Char('R') => {
                            last_auto_refresh = Instant::now();
                            {
                                let mut s = state.lock().await;
                                s.refreshing = true;
                            }
                            let (btc, svcs, anc) = refresh(&cfg, &http_client).await;
                            let mut s = state.lock().await;
                            s.bitcoin = btc;
                            s.services = svcs;
                            s.anchor = anc;
                            s.last_refresh = Some(Instant::now());
                            s.refreshing = false;
                            s.log.push(format!(
                                "{} manual refresh",
                                chrono::Utc::now().format("%H:%M:%S")
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }

        // Auto-refresh
        if last_auto_refresh.elapsed() >= refresh_interval {
            last_auto_refresh = Instant::now();
            {
                let mut s = state.lock().await;
                s.refreshing = true;
            }
            let (btc, svcs, anc) = refresh(&cfg, &http_client).await;
            let mut s = state.lock().await;
            let healthy = svcs.iter().filter(|s| s.healthy).count();
            let total = svcs.len();
            s.bitcoin = btc;
            s.services = svcs;
            s.anchor = anc;
            s.last_refresh = Some(Instant::now());
            s.refreshing = false;
            s.log.push(format!(
                "{} auto refresh — {}/{} services up",
                chrono::Utc::now().format("%H:%M:%S"),
                healthy,
                total
            ));
            // Keep log bounded
            if s.log.len() > 200 {
                s.log.drain(0..100);
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
