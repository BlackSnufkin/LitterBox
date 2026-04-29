# LitterBox Roadmap — Elastic EDR Integration

## Overview

Goal: let LitterBox dispatch a payload to a separate user-managed Windows VM
that runs Elastic Defend, then query the user's local Elastic stack for any
detection alerts raised against that execution.

**Out of scope** (user-managed):
- Deploying the Elastic stack — point users to
  [elastic-container-project](https://www.elastic.co/security-labs/the-elastic-container-project)
  for a self-hosted Elasticsearch + Kibana + Fleet setup.
- Provisioning the EDR VM — the user brings their own Windows VM with
  Elastic Defend already enrolled.
- Running anything in the cloud. Everything is local / self-hosted.

**In scope** (this project):
- Build **Whiskers** in Rust — a single-binary Windows execution runner
  that the user drops on their EDR VM. Receives a payload over HTTP, executes
  it, reports stdout/stderr/PID. **No local EDR reading, no log scraping —
  the Elastic Agent already on the VM handles all telemetry.**
- Build **LitterBox-side integration** — a new analyzer module that talks to
  the agent's REST API + queries the user's local Elastic for alerts in the
  run window.

**Design constraint — single-occupancy:**

The agent runs one payload at a time. No parallel execution, no queue, no
slot management. The `acquire/release` lock is the primitive that enforces
this — it covers the whole orchestration window (exec start through Elastic
poll completion), not just the live-process window. New exec while a run is
in progress is rejected with 409.

## Architecture

```
LitterBox (existing, on Windows analysis machine)
  │
  └─ NEW: ElasticEdrAnalyzer
       │
       ├── HTTP ──► Whiskers (user's EDR VM, our Rust binary)
       │              ├── exec / kill / lock
       │              └── stdout / stderr / PID reporting
       │
       └── HTTP ──► User's local Elastic stack (their elastic-container-project)
                      └── /.siem-signals-*/_search filtered by host.name + time

User's EDR VM (their responsibility)
  ├── Whiskers.exe (our Rust binary, running on :8080)
  └── Elastic Agent + Elastic Defend (user-installed, enrolled to their Elastic stack)
```

The agent is the only deliverable on the VM side. EDR telemetry comes from
the Elastic Agent the user installed separately. LitterBox queries the user's
Elastic stack via REST. No cloud anywhere.

## Deployment matrix

LitterBox itself has two deploy methods (unchanged by this work):

1. **Direct Windows host** — user clones the repo, `python -m venv venv`,
   `pip install -r requirements.txt`, runs LitterBox. No install script.
2. **Docker on Linux** — `Docker/setup.sh` provisions a `dockurr/windows`
   container; `Docker/install.ps1` bootstraps LitterBox inside the
   freshly-provisioned Windows VM.

This work is **backward-compatible by design** — every existing user's
deployment continues working unchanged. Elastic capability is purely
additive: drop a profile YAML, point at an agent URL, enable.

## Roadmap

### Phase A — Whiskers (Rust)

**Build the agent first; nothing in Phase L can be tested end-to-end without it.**

#### A1. Project scaffold
- Cargo project, tokio async runtime, axum web framework (minimal modern HTTP)
- Cross-compile target: `x86_64-pc-windows-gnu` from Linux, or
  `x86_64-pc-windows-msvc` from Windows
- Goal: hello-world endpoint compiling to a single static `.exe`

#### A2. REST endpoints (the entire agent surface)

| Endpoint | Behaviour |
|---|---|
| `GET /api/info` | `{"hostname": ..., "os_version": ..., "agent_version": ...}` — agent self-reports its identity. LitterBox uses the hostname to filter Elastic alerts; user never configures it manually. |
| `GET /api/lock/status` | `{"in_use": bool}` |
| `POST /api/lock/acquire` | 200 if free, 409 if held |
| `POST /api/lock/release` | 200 |
| `POST /api/execute/exec` | multipart (`file`, optional `drop_path`, `executable_args`, `xor_key`) → spawn the file, return `{status, pid}` |
| `POST /api/execute/kill` | terminate the spawned process if alive |
| `GET /api/logs/execution` | `{pid, stdout, stderr, exit_code}` for the last run |
| `GET /api/logs/agent` | agent's own debug log for troubleshooting |

That is the whole agent. No EDR plugins, no log scraping, no Windows Event
Log integration. Just an execution runner that knows its own hostname.

#### A3. Build pipeline
- `cargo build --release --target x86_64-pc-windows-gnu` → `Whiskers.exe`
- Single static binary, no runtime dependencies on the target VM
- Ship in GitHub releases as a downloadable `.exe`

#### A4. Agent install docs
- Drop the `.exe` on the EDR VM, run `Whiskers.exe --port 8080`
- Allow inbound TCP 8080 in Windows Firewall
- Optional: register as a Windows service via `sc create`

**Deliverable after Phase A**: a standalone `.exe` that any user can drop on
any Windows VM. Verifiable with `curl http://<vm>:8080/api/lock/status`.

---

### Phase L — LitterBox-side integration

#### L1. Profile YAML schema + loader

```yaml
# Config/edr_profiles/elastic.yml
name: "elastic"
display_name: "Elastic Defend"
agent_url: "http://<edr-vm-ip>:8080"
elastic_url: "https://<elastic-stack-ip>:9200"
elastic_apikey: "<base64-encoded-key>"
wait_seconds_for_alerts: 90            # Elastic's detection rule cycle is ~60s
# hostname is NOT configured here — agent self-reports via GET /api/info
# at the start of each run. If user moves the agent to a different VM,
# LitterBox picks up the new hostname automatically with no config edit.
```

Loader scans `Config/edr_profiles/*.yml` at LitterBox boot and registers
each profile. Real profile files are gitignored; ship a `.example` template.

#### L2. AgentClient
- `app/analyzers/edr/agent_client.py`
- Python REST wrapper for the Rust agent's API
- Methods: `lock_acquire`, `lock_release`, `lock_status`, `exec(file_bytes, drop_path, args, xor_key)`, `kill`, `get_execution_logs`, `get_agent_logs`
- Fail-soft: if agent unreachable, profile is marked unavailable in UI

#### L3. ElasticClient
- `app/analyzers/edr/elastic_client.py`
- `GET <elastic_url>/.siem-signals-*/_search` with `Authorization: ApiKey <key>`
- Filter by `kibana.alert.original_time` range + `host.name`
- Returns normalized alert records: `{title, severity, rule_id, detected_at, raw}`

#### L4. ElasticEdrAnalyzer (orchestrator)

Per-payload flow:

1. `AgentClient.get_info` → `{hostname, os_version, agent_version}` (self-reported)
2. `AgentClient.lock_acquire`
3. `AgentClient.exec(payload, args)`
4. wait for execution to exit OR timeout
5. `AgentClient.kill` (idempotent if already exited)
6. `AgentClient.get_execution_logs` → stdout / stderr / exit_code
7. sleep `wait_seconds_for_alerts` (allow Elastic detection rule cycle)
8. `ElasticClient.fetch_alerts(hostname_from_step_1, run_start, now)`
9. `AgentClient.lock_release`
10. return `findings` dict

**Deliverable after Phase L**: end-to-end works from CLI / API. Submit a
payload, get back execution output + Elastic alerts.

---

### Phase U — UI

#### U1. Upload-page integration
- "Run with Elastic" button on upload page (one button per registered profile)
- Profile YAML's `display_name` becomes the button label
- Sits next to existing Static / Dynamic / HolyGrail buttons

#### U2. Results-page tab
- New "Elastic" tab when the profile was used
- Sub-sections: Execution output | Elastic Alerts | Verdict line at top
- Detection Score contribution: high/critical-severity Elastic alerts → +50
  (mirrors the existing Defender pattern in `_calculate_rededr_risk`)

---

### Phase R — Report

#### R1. Self-contained downloadable report
- Add an EDR section to `app/templates/report.html`
- Same content as the U2 tab — verdict line, alert table, execution output

---

### Phase D — Docs

#### D1. README + setup docs
- **"Setting up Elastic for LitterBox"** — point to
  [elastic-container-project](https://www.elastic.co/security-labs/the-elastic-container-project),
  list the minimum config the user needs:
  - Elastic Defend integration enabled
  - EDR VM enrolled to their Fleet
  - Detection Engine rules enabled
  - API key with `.siem-signals-*` read scope
- **"Deploying Whiskers"** — drop the `.exe`, run with `--port`,
  allow firewall, optional Windows-service registration
- **"Configuring LitterBox profile"** — copy `Config/edr_profiles/elastic.yml.example`,
  fill 4 fields (`agent_url`, `elastic_url`, `elastic_apikey`, `hostname`),
  restart LitterBox

---

## Critical path

```
A1 → A2 → A3 → A4   (testable agent binary)
                  │
                  ▼
              L1 → L2 → L3 → L4   (testable end-to-end)
                                │
                                ▼
                            U1 → U2 → R1 → D1
```

Phase A is the gate — until the Rust agent compiles and runs on a Windows VM,
nothing in Phase L can be tested end-to-end. After A, L1-L4 are straight
Python work in the existing LitterBox codebase.

## Critical files

### New (Phase A — separate Rust crate)
- `Whiskers/Cargo.toml`
- `Whiskers/src/main.rs` — entry, axum router setup
- `Whiskers/src/api/{lock,execute,logs}.rs` — endpoint handlers
- `Whiskers/src/state.rs` — shared lock + execution state

### New (Phase L — LitterBox repo)
- `Config/edr_profiles/elastic.yml.example`
- `app/analyzers/edr/__init__.py`
- `app/analyzers/edr/agent_client.py`
- `app/analyzers/edr/elastic_client.py`
- `app/analyzers/edr/elastic_edr_analyzer.py`
- `app/analyzers/edr/profile_loader.py`

### Modified (Phase L–R — LitterBox repo)
- `app/analyzers/manager.py` — register ElasticEdrAnalyzer
- `app/blueprints/api.py` — new endpoint to dispatch to a profile
- `app/templates/upload.html` — "Run with X" buttons from profile registry
- `app/templates/results.html` — new tab when an EDR profile was used
- `app/templates/report.html` — new EDR section
- `app/utils/risk_analyzer.py` — Elastic alert contribution to Detection Score
- `README.md` — add the EDR section pointing to elastic-container-project

## Out of scope (deferred / never)

- **Cloud EDR integrations** (Elastic Cloud, MDE Graph, CrowdStrike Cloud) —
  this project is local-only.
- **EDR VM provisioning / docker-compose for the EDR VM** — user brings their
  own VM with their own EDR.
- **Elastic stack deployment** — point to elastic-container-project, do not
  ship our own.
- **Multiple EDR types beyond Elastic** — agent's API surface is generic
  enough that adding another EDR is a matter of writing another `*_client.py`
  in `app/analyzers/edr/` and another profile YAML, but we don't ship more
  than Elastic in v1.
- **Multi-VM parallel runs / snapshot revert per submission** — accept VM
  state accumulation; user reboots / reverts the VM manually if needed.
- **Profile-management UI** — YAML edit + restart is sufficient for v1.

## Verification

End-to-end after Phase L:

1. User deploys Elastic stack via elastic-container-project on a Linux box
2. User stands up a Windows VM, installs Elastic Agent + Elastic Defend,
   enrolls to their stack
3. User drops `Whiskers.exe` on that VM, runs it with `--port 8080`
4. User configures `Config/edr_profiles/elastic.yml` with the 4 fields
5. User uploads a known-detected sample to LitterBox, clicks "Run with Elastic"
6. Within ~90s after the payload executes, alerts appear in the Elastic tab
   matching what Kibana shows in the Detection Engine alerts page
7. High/critical alerts visibly bump the Detection Score on the file's
   info page

If steps 5–7 work for a known Elastic-detected sample (e.g. a stock mimikatz
build), the integration is functional.
