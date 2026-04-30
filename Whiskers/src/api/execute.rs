//! `POST /api/execute/exec` · `POST /api/execute/kill`
//!
//! `exec` is multipart: a binary `file` + optional `drop_path`,
//! `executable_args`, `xor_key`. Writes the file, spawns it, returns
//! `{status, pid}` immediately. A detached tokio task watches the spawned
//! process — on exit (or kill request) it captures stdout/stderr into
//! `RunState`, where `GET /api/logs/execution` reads them later.
//!
//! Single-occupancy by design: a new `exec` while a previous run is still
//! alive will kill the previous run first, then start the new one. The
//! orchestrator's lock is what prevents that situation in normal use; this
//! is just defensive cleanup.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use axum::extract::{Multipart, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::Serialize;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::oneshot;

use crate::file_writer;
use crate::state::{AppState, ExecStatus, RunState};

const DEFAULT_DROP_PATH: &str = r"C:\Users\Public\Downloads\";

#[derive(Serialize)]
pub struct ExecResponse {
    pub status: &'static str,
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Serialize)]
pub struct KillResponse {
    pub status: &'static str,
    pub message: String,
}

/// Multipart form body for `/api/execute/exec`.
struct ExecForm {
    file_name: String,
    file_bytes: Vec<u8>,
    drop_path: String,
    executable_args: Option<String>,
    xor_key: Option<u8>,
}

pub async fn exec(
    State(state): State<Arc<AppState>>,
    multipart: Multipart,
) -> Result<Json<ExecResponse>, (StatusCode, Json<ExecResponse>)> {
    let form = match parse_multipart(multipart).await {
        Ok(form) => form,
        Err(err) => {
            tracing::warn!(error = %err, "Exec request multipart parse failed");
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ExecResponse {
                    status: "error",
                    pid: None,
                    message: Some(err),
                }),
            ));
        }
    };

    if form.file_bytes.is_empty() || form.file_name.trim().is_empty() {
        tracing::warn!("Exec rejected: empty file or filename");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ExecResponse {
                status: "error",
                pid: None,
                message: Some("Invalid request: filename or file data is missing".into()),
            }),
        ));
    }

    let file_path = build_drop_path(&form.drop_path, &form.file_name);
    tracing::info!(path = %file_path.display(), xor = form.xor_key.is_some(), "Writing payload");

    if let Err(err) = file_writer::write(&file_path, &form.file_bytes, form.xor_key).await {
        // AV intercepts on write usually surface as IO error or "permission denied".
        // Distinguish if we can; otherwise treat as generic write failure.
        tracing::error!(error = %err, "Failed to write payload");
        let virus_signaled = is_likely_av_block(&err);
        if virus_signaled {
            // 200 OK — the agent successfully detected an AV intercept.
            // It's a real outcome of the run, not a transport-level error.
            return Ok(Json(ExecResponse {
                status: "virus",
                pid: None,
                message: Some(format!("Antivirus blocked write: {err}")),
            }));
        }
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ExecResponse {
            status: "error",
            pid: None,
            message: Some(format!("Failed to write file: {err}")),
        })));
    }

    // Kill any previous run that's still hanging around (defensive — orchestrator
    // should have called kill, but if it didn't, don't leave orphans).
    take_previous_run_for_cleanup(&state).await;

    // Spawn the payload. Windows can't directly exec a `.dll` — those need
    // to go through `rundll32.exe <dll>,<entry-point> [args...]`. The
    // entry point is required and comes from `executable_args`; if it's
    // missing we bail with a clear error instead of letting Windows
    // return ERROR_BAD_EXE_FORMAT.
    let is_dll = file_path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case("dll"))
        .unwrap_or(false);
    let executable_args = form.executable_args.as_deref().unwrap_or("").trim();

    let mut command = if is_dll {
        if executable_args.is_empty() {
            tracing::error!("DLL spawn rejected: no entry point provided in executable_args");
            let _ = tokio::fs::remove_file(&file_path).await;
            return Err((StatusCode::BAD_REQUEST, Json(ExecResponse {
                status: "error",
                pid: None,
                message: Some(
                    "DLL execution requires an entry point in executable_args \
                     (rundll32 syntax: <ExportedFunction> [args...])".into(),
                ),
            })));
        }
        // Split the args: the first token is the export name (becomes
        // `<dll>,<export>`), everything after is forwarded to rundll32.
        let mut tokens = executable_args.split_whitespace();
        let entry = tokens.next().unwrap();   // checked non-empty above
        let rest: Vec<&str> = tokens.collect();
        let dll_target = format!("{},{}", file_path.display(), entry);
        tracing::info!(dll = %file_path.display(), entry, "Spawning DLL via rundll32");
        let mut c = Command::new("rundll32.exe");
        c.arg(dll_target);
        for r in rest { c.arg(r); }
        c
    } else {
        let mut c = Command::new(&file_path);
        if !executable_args.is_empty() {
            c.args(parse_args(executable_args));
        }
        c
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            tracing::error!(error = %err, "Failed to spawn payload");
            // Treat NotFound as legitimate failure; PermissionDenied / "operation
            // aborted" usually mean the AV killed the spawn.
            let virus_signaled = is_likely_av_block(&err);
            // Best-effort cleanup of the dropper.
            let _ = tokio::fs::remove_file(&file_path).await;
            if virus_signaled {
                return Ok(Json(ExecResponse {
                    status: "virus",
                    pid: None,
                    message: Some(format!("Antivirus blocked spawn: {err}")),
                }));
            }
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ExecResponse {
                status: "error",
                pid: None,
                message: Some(format!("Failed to spawn process: {err}")),
            })));
        }
    };

    let pid = child.id().unwrap_or(0);
    tracing::info!(pid, "Payload spawned");

    // Take stdout/stderr handles for the monitor task.
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    // Set up the kill channel before we hand the child to the monitor.
    let (kill_tx, kill_rx) = oneshot::channel::<()>();

    {
        let mut run_slot = state.run.lock().unwrap();
        *run_slot = Some(RunState {
            pid,
            started_at: Utc::now(),
            finished_at: None,
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
            status: ExecStatus::Running,
            cleanup_files: vec![file_path.clone()],
            child_kill_tx: Some(kill_tx),
        });
    }

    // Detached monitor task — owns the Child, captures output, updates state on exit.
    tokio::spawn(monitor_run(child, stdout, stderr, kill_rx, Arc::clone(&state)));

    Ok(Json(ExecResponse {
        status: "ok",
        pid: Some(pid),
        message: None,
    }))
}

pub async fn kill(State(state): State<Arc<AppState>>) -> Json<KillResponse> {
    let kill_tx = {
        let mut run_slot = state.run.lock().unwrap();
        match run_slot.as_mut() {
            None => {
                tracing::info!("Kill: no run to kill");
                return Json(KillResponse {
                    status: "ok",
                    message: "No execution to kill".into(),
                });
            }
            Some(run) => {
                if run.status != ExecStatus::Running {
                    tracing::info!(pid = run.pid, status = run.status.as_str(), "Kill: run already finished");
                    return Json(KillResponse {
                        status: "ok",
                        message: format!("Run already {}", run.status.as_str()),
                    });
                }
                run.child_kill_tx.take()
            }
        }
    };

    if let Some(tx) = kill_tx {
        // Best-effort signal — if the receiver is gone (process exited mid-flight),
        // that's fine, the monitor task will have already updated the state.
        let _ = tx.send(());
        tracing::info!("Kill signal sent to monitor task");
    }

    // Cleanup files happens in the monitor task on exit — give it a moment.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    Json(KillResponse {
        status: "ok",
        message: "Kill signal delivered".into(),
    })
}

/// Watches the spawned child until it exits or until the kill channel fires,
/// then captures stdout/stderr, deletes dropped files, and updates `RunState`.
async fn monitor_run(
    mut child: Child,
    stdout: Option<tokio::process::ChildStdout>,
    stderr: Option<tokio::process::ChildStderr>,
    mut kill_rx: oneshot::Receiver<()>,
    state: Arc<AppState>,
) {
    let pid = child.id().unwrap_or(0);

    let stdout_task = tokio::spawn(async move {
        if let Some(mut s) = stdout {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
            String::from_utf8_lossy(&buf).into_owned()
        } else {
            String::new()
        }
    });
    let stderr_task = tokio::spawn(async move {
        if let Some(mut s) = stderr {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
            String::from_utf8_lossy(&buf).into_owned()
        } else {
            String::new()
        }
    });

    // Wait for either natural exit or kill request. After kill is requested,
    // we still need to wait for the process to actually terminate so we can
    // capture its (possibly partial) output.
    let mut killed = false;
    let exit_status = loop {
        tokio::select! {
            result = child.wait() => break result,
            kill_result = &mut kill_rx => {
                if kill_result.is_ok() {
                    if let Err(err) = child.start_kill() {
                        tracing::warn!(pid, error = %err, "start_kill failed");
                    } else {
                        killed = true;
                        tracing::info!(pid, "Sent kill to child process");
                    }
                }
                // Continue waiting for actual exit.
                let exit = child.wait().await;
                break exit;
            }
        }
    };

    let stdout = stdout_task.await.unwrap_or_default();
    let stderr = stderr_task.await.unwrap_or_default();

    let exit_code = exit_status.as_ref().ok().and_then(|s| s.code());

    let cleanup_files = {
        let mut run_slot = state.run.lock().unwrap();
        if let Some(run) = run_slot.as_mut() {
            // If a newer exec replaced this run's slot, this cast won't match.
            // We compare by PID to avoid clobbering the new run's state.
            if run.pid == pid {
                run.finished_at = Some(Utc::now());
                run.stdout = stdout;
                run.stderr = stderr;
                run.exit_code = exit_code;
                run.status = if killed {
                    ExecStatus::Killed
                } else {
                    ExecStatus::Exited
                };
                run.child_kill_tx = None;
                std::mem::take(&mut run.cleanup_files)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    };

    tracing::info!(
        pid,
        exit_code = ?exit_code,
        killed,
        "Run finished"
    );

    // Best-effort cleanup of dropped files. Brief delay so AV / handle lock
    // releases first.
    if !cleanup_files.is_empty() {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        for path in cleanup_files {
            if let Err(err) = tokio::fs::remove_file(&path).await {
                tracing::warn!(path = %path.display(), error = %err, "Cleanup remove failed");
            } else {
                tracing::info!(path = %path.display(), "Cleanup removed");
            }
        }
    }
}

/// If the previous run is still alive, signal it to die before we start a
/// new one. Best-effort — orchestrator should have called kill itself.
async fn take_previous_run_for_cleanup(state: &Arc<AppState>) {
    let kill_tx = {
        let mut run_slot = state.run.lock().unwrap();
        match run_slot.as_mut() {
            Some(run) if run.status == ExecStatus::Running => {
                tracing::warn!(pid = run.pid, "Previous run still alive — killing before new exec");
                run.child_kill_tx.take()
            }
            _ => None,
        }
    };
    if let Some(tx) = kill_tx {
        let _ = tx.send(());
    }
}

/// Heuristic for "did Windows AV block this?" — we can't reliably distinguish
/// "AV intercepted" from "OS access denied" without parsing OS error codes,
/// but ERROR_VIRUS_INFECTED (225) and ERROR_OPERATION_ABORTED (995) are the
/// usual signals.
fn is_likely_av_block(err: &std::io::Error) -> bool {
    match err.raw_os_error() {
        Some(225) | Some(995) | Some(1234) => true, // ERROR_VIRUS_INFECTED, ABORTED, etc.
        _ => false,
    }
}

/// Build the final on-disk path: `<drop_path>/<file_name>`. Defaults
/// drop_path to `C:\Users\Public\Downloads\` if not provided.
fn build_drop_path(drop_path: &str, file_name: &str) -> PathBuf {
    let mut base = if drop_path.trim().is_empty() {
        DEFAULT_DROP_PATH.to_string()
    } else {
        drop_path.to_string()
    };
    if !base.ends_with('\\') && !base.ends_with('/') {
        base.push('\\');
    }
    Path::new(&base).join(file_name)
}

/// Trivial argument splitter — splits on whitespace, ignoring quoting. Good
/// enough for the typical "--flag value --other" payload args; orchestrator
/// can pre-shell-escape if needed.
fn parse_args(s: &str) -> Vec<&str> {
    s.split_whitespace().collect()
}

/// Pull the multipart body into our `ExecForm`. Bytes are buffered in
/// memory — payload sizes are normally tens of MB, well within reasonable
/// limits.
async fn parse_multipart(mut multipart: Multipart) -> Result<ExecForm, String> {
    let mut file_name = String::new();
    let mut file_bytes = Vec::new();
    let mut drop_path = String::new();
    let mut executable_args: Option<String> = None;
    let mut xor_key: Option<u8> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| format!("multipart read error: {e}"))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                file_name = field
                    .file_name()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| format!("file read error: {e}"))?;
                file_bytes = bytes.to_vec();
            }
            "drop_path" => {
                drop_path = field
                    .text()
                    .await
                    .map_err(|e| format!("drop_path read error: {e}"))?;
            }
            "executable_args" => {
                let s = field
                    .text()
                    .await
                    .map_err(|e| format!("executable_args read error: {e}"))?;
                if !s.is_empty() {
                    executable_args = Some(s);
                }
            }
            "xor_key" => {
                let s = field
                    .text()
                    .await
                    .map_err(|e| format!("xor_key read error: {e}"))?;
                let n: i32 = s
                    .parse()
                    .map_err(|_| format!("xor_key not an integer: {s:?}"))?;
                if !(0..=255).contains(&n) {
                    return Err(format!("xor_key out of range 0-255: {n}"));
                }
                xor_key = Some(n as u8);
            }
            "execution_mode" => {
                // Currently ignored — only "exec" mode supported. Accepted for
                // forward compatibility with DetonatorAgent's protocol.
                let _ = field.text().await;
            }
            other => {
                tracing::debug!(field = %other, "Ignoring unknown multipart field");
                let _ = field.bytes().await;
            }
        }
    }

    Ok(ExecForm {
        file_name,
        file_bytes,
        drop_path,
        executable_args,
        xor_key,
    })
}
