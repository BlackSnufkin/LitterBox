//! Shared in-memory state.
//!
//! Two coarse mutexes — one for the lock primitive, one for the single
//! "current run" slot. Single-occupancy by design, so the slot is overwritten
//! on each new exec rather than queued.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use tokio::sync::oneshot;

use crate::agent_log::AgentLog;

/// Top-level state passed to every handler via `axum::extract::State<Arc<AppState>>`.
pub struct AppState {
    pub lock: Mutex<LockState>,
    pub run: Mutex<Option<RunState>>,
    pub agent_log: Arc<AgentLog>,
}

impl AppState {
    pub fn new(agent_log: Arc<AgentLog>) -> Arc<Self> {
        Arc::new(AppState {
            lock: Mutex::new(LockState::default()),
            run: Mutex::new(None),
            agent_log,
        })
    }
}

/// Lock primitive — single-occupancy gate the orchestrator holds across
/// the whole exec → poll → release window. Self-heals after `LOCK_TIMEOUT`
/// to recover from a crashed orchestrator.
#[derive(Default)]
pub struct LockState {
    pub held: bool,
    pub acquired_at: Option<DateTime<Utc>>,
}

/// Auto-release stale locks after this duration. Matches DetonatorAgent
/// (30 minutes) — long enough for a slow Elastic-poll window to complete,
/// short enough that a forgotten lock doesn't strand the agent.
pub const LOCK_TIMEOUT_MINUTES: i64 = 30;

impl LockState {
    /// Returns `true` if the stored lock has expired and was reset.
    /// Caller checks this BEFORE consulting `held` so status reflects
    /// post-cleanup state.
    pub fn maybe_expire(&mut self) -> bool {
        if !self.held {
            return false;
        }
        let Some(acquired_at) = self.acquired_at else {
            return false;
        };
        let age = Utc::now().signed_duration_since(acquired_at);
        if age.num_minutes() >= LOCK_TIMEOUT_MINUTES {
            self.held = false;
            self.acquired_at = None;
            return true;
        }
        false
    }
}

/// Tracking for the most recent `/api/execute/exec` request. Overwritten on
/// each new exec — there's no history. `child_kill_tx` lets the kill handler
/// signal the monitor task to terminate the child without sharing the
/// `tokio::process::Child` handle across threads.
pub struct RunState {
    pub pid: u32,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub status: ExecStatus,
    pub cleanup_files: Vec<PathBuf>,
    /// `Some` while the monitor task is alive; taken when kill is requested.
    /// `None` if the run already finished (kill is then a no-op).
    pub child_kill_tx: Option<oneshot::Sender<()>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // BlockedByAv is reserved for the AV-intercept code path
                     // that's wired in execute.rs but only triggers when the
                     // AV emits ERROR_VIRUS_INFECTED on spawn.
pub enum ExecStatus {
    Running,
    Exited,
    Killed,
    /// Antivirus blocked the dropper / spawn.
    BlockedByAv,
}

impl ExecStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExecStatus::Running => "running",
            ExecStatus::Exited => "exited",
            ExecStatus::Killed => "killed",
            ExecStatus::BlockedByAv => "blocked_by_av",
        }
    }
}
