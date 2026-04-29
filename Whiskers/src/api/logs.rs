//! `GET /api/logs/execution` · `GET /api/logs/agent` · `DELETE /api/logs/agent`
//!
//! Read-back endpoints. `execution` returns the most recent run's output
//! (PID, stdout, stderr, exit code, status). `agent` returns the agent's
//! own debug log buffer.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub struct ExecutionLogs {
    pub pid: u32,
    pub status: &'static str,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub is_running: bool,
}

pub async fn execution(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ExecutionLogs>, (StatusCode, &'static str)> {
    let run = state.run.lock().unwrap();
    let Some(run) = run.as_ref() else {
        return Err((StatusCode::BAD_REQUEST, "No execution recorded"));
    };

    Ok(Json(ExecutionLogs {
        pid: run.pid,
        status: run.status.as_str(),
        stdout: run.stdout.clone(),
        stderr: run.stderr.clone(),
        exit_code: run.exit_code,
        started_at: Some(run.started_at.to_rfc3339()),
        finished_at: run.finished_at.map(|t| t.to_rfc3339()),
        is_running: matches!(
            run.status,
            crate::state::ExecStatus::Running
        ),
    }))
}

pub async fn agent_logs(State(state): State<Arc<AppState>>) -> String {
    state.agent_log.snapshot().join("\n")
}

pub async fn clear_agent_logs(State(state): State<Arc<AppState>>) -> &'static str {
    state.agent_log.clear();
    tracing::info!("Agent logs cleared via API");
    "Agent logs cleared"
}
