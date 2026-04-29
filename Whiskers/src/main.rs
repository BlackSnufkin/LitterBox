//! Whiskers — LitterBox's sensor agent. HTTP execution runner deployed on
//! the user's EDR VM.
//!
//! Single-binary, single-occupancy. Receives a payload via HTTP, executes
//! it on the host, reports stdout/stderr/PID/exit_code back to LitterBox.
//! Does not read local EDR alerts — telemetry comes from whatever EDR agent
//! (e.g. Elastic Defend) the user installed on the same VM independently.
//! LitterBox queries the EDR's backend separately for the verdict.

use std::net::{IpAddr, SocketAddr};

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};
use axum::Router;
use clap::Parser;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod agent_log;
mod api;
mod file_writer;
mod state;

use crate::agent_log::{AgentLog, AgentLogLayer};
use crate::state::AppState;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(name = "whiskers", version, about = "Whiskers — LitterBox's sensor agent")]
struct Cli {
    /// TCP port to listen on. LitterBox connects to this from its profile YAML.
    #[arg(long, default_value_t = 8080)]
    port: u16,

    /// Bind address. Default 0.0.0.0 so the orchestrator on a different host
    /// can reach the agent. Set to 127.0.0.1 for loopback-only testing.
    #[arg(long, default_value = "0.0.0.0")]
    bind: IpAddr,

    /// Max payload size in megabytes for /api/execute/exec multipart uploads.
    /// LitterBox's default upload cap is 100 MB; we mirror that with a small
    /// margin for the multipart envelope. Override if your environment
    /// dispatches larger samples.
    #[arg(long, default_value_t = 200)]
    max_payload_mb: usize,
}

#[tokio::main]
async fn main() {
    // Build the agent log buffer first; we'll install it as a tracing layer
    // so every log line gets mirrored into it AND printed to stdout.
    let agent_log = std::sync::Arc::new(AgentLog::new());

    let stdout_layer = tracing_subscriber::fmt::layer().with_target(false);
    let log_buffer_layer = AgentLogLayer::new(std::sync::Arc::clone(&agent_log));
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info".into());

    tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(log_buffer_layer)
        .init();

    let cli = Cli::parse();
    let addr = SocketAddr::new(cli.bind, cli.port);
    let max_payload_bytes = cli.max_payload_mb.saturating_mul(1024 * 1024);

    let state = AppState::new(agent_log);

    // axum's default multipart body limit is 2 MiB — too small for real
    // payloads. Disable the route-level cap and re-impose our own via
    // RequestBodyLimitLayer so we can configure it from the CLI.
    let exec_router = Router::new()
        .route("/api/execute/exec", post(api::execute::exec))
        .layer(DefaultBodyLimit::max(max_payload_bytes));

    let app = Router::new()
        .route("/api/info", get(api::info::get_info))
        .route("/api/lock/acquire", post(api::lock::acquire))
        .route("/api/lock/release", post(api::lock::release))
        .route("/api/lock/status", get(api::lock::status))
        .merge(exec_router)
        .route("/api/execute/kill", post(api::execute::kill))
        .route("/api/logs/execution", get(api::logs::execution))
        .route("/api/logs/agent", get(api::logs::agent_logs))
        .route("/api/logs/agent", delete(api::logs::clear_agent_logs))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind listen address");

    tracing::info!(
        version = AGENT_VERSION,
        listen = %addr,
        max_payload_mb = cli.max_payload_mb,
        "Whiskers ready"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

/// Shut down cleanly on Ctrl-C / SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
