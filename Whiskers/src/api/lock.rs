//! `POST /api/lock/acquire` · `POST /api/lock/release` · `GET /api/lock/status`
//!
//! Single-occupancy gate the orchestrator holds across the whole run window
//! (exec start → Elastic poll completion → release). Self-heals stale locks
//! after `LOCK_TIMEOUT_MINUTES` so a crashed orchestrator can't strand the
//! agent forever.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub struct LockStatus {
    pub in_use: bool,
}

#[derive(Serialize)]
pub struct LockError {
    pub status: &'static str,
    pub message: &'static str,
}

pub async fn acquire(
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, (StatusCode, Json<LockError>)> {
    let mut lock = state.lock.lock().unwrap();
    if lock.maybe_expire() {
        tracing::warn!("Lock auto-expired before acquire — recovering");
    }
    if lock.held {
        tracing::warn!("Lock acquire rejected — already held");
        return Err((
            StatusCode::CONFLICT,
            Json(LockError {
                status: "error",
                message: "Resource is already in use",
            }),
        ));
    }
    lock.held = true;
    lock.acquired_at = Some(Utc::now());
    tracing::info!("Lock acquired");
    Ok(StatusCode::OK)
}

pub async fn release(State(state): State<Arc<AppState>>) -> StatusCode {
    let mut lock = state.lock.lock().unwrap();
    if !lock.held {
        tracing::info!("Lock release on already-free lock");
    }
    lock.held = false;
    lock.acquired_at = None;
    tracing::info!("Lock released");
    StatusCode::OK
}

pub async fn status(State(state): State<Arc<AppState>>) -> Json<LockStatus> {
    let mut lock = state.lock.lock().unwrap();
    if lock.maybe_expire() {
        tracing::warn!("Lock auto-expired during status check");
    }
    Json(LockStatus { in_use: lock.held })
}
