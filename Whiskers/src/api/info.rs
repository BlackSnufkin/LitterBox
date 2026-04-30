//! `GET /api/info` — agent self-reports its identity so LitterBox can
//! filter Elastic alerts by the host's actual hostname without the operator
//! configuring it manually. `telemetry_sources` lets the orchestrator
//! preflight which alert pipelines this VM can serve (currently: Fibratus
//! installed-or-not).

use std::path::Path;

use axum::Json;
use serde::Serialize;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default Fibratus install path. LitterBox treats the presence of this
/// binary as the cheap probe for "this VM can serve Fibratus alerts."
const FIBRATUS_EXE: &str = r"C:\Program Files\Fibratus\Bin\fibratus.exe";

#[derive(Serialize)]
pub struct AgentInfo {
    pub hostname: String,
    pub os_version: String,
    pub agent_version: &'static str,
    /// Names of additional telemetry pipelines this VM can serve. The
    /// orchestrator dispatches a profile of `kind: fibratus` only when
    /// `"fibratus"` appears in this list.
    pub telemetry_sources: Vec<&'static str>,
}

pub async fn get_info() -> Json<AgentInfo> {
    let hostname = gethostname::gethostname()
        .into_string()
        .unwrap_or_else(|_| "unknown".to_string());
    let os_version = os_info::get().to_string();

    let mut telemetry_sources: Vec<&'static str> = Vec::new();
    if has_fibratus() {
        telemetry_sources.push("fibratus");
    }

    Json(AgentInfo {
        hostname,
        os_version,
        agent_version: AGENT_VERSION,
        telemetry_sources,
    })
}

/// Cheap "is Fibratus installed here?" check. Just a stat — we do not
/// run the binary or query the event log on every /api/info hit.
pub fn has_fibratus() -> bool {
    Path::new(FIBRATUS_EXE).exists()
}
