//! `GET /api/info` — agent self-reports its identity so LitterBox can
//! filter Elastic alerts by the host's actual hostname without the operator
//! configuring it manually.

use axum::Json;
use serde::Serialize;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize)]
pub struct AgentInfo {
    pub hostname: String,
    pub os_version: String,
    pub agent_version: &'static str,
}

pub async fn get_info() -> Json<AgentInfo> {
    let hostname = gethostname::gethostname()
        .into_string()
        .unwrap_or_else(|_| "unknown".to_string());
    let os_version = os_info::get().to_string();

    Json(AgentInfo {
        hostname,
        os_version,
        agent_version: AGENT_VERSION,
    })
}
