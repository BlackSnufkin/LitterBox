LitterBox v5.0.0 is a major release. New EDR-integration pipeline (Elastic + Fibratus) backed by the **Whiskers** Rust agent, a system dashboard at `/`, a full backend / frontend refactor onto Flask blueprints + ES6 modules, and a perf cluster (parallel static analyzers, mtime-validated dashboard cache, lazy saved-views, adaptive polling). Drop `Whiskers.exe` on your EDR VM, copy a profile YAML from `Config/edr_profiles/*.yml.example`, restart LitterBox — the new profile button appears on the upload page.

## Downloads

| File | Purpose |
|---|---|
| `Whiskers.exe` | Single-binary Rust agent — drop on the EDR-instrumented Windows VM. |
| `Whiskers.exe.sha256` | SHA256 of the binary — verify the download before deploying. |
| `Source code (zip / tar.gz)` | Auto-attached by GitHub. Full LitterBox source at this tag. |

## Verifying the binary

```powershell
Get-FileHash Whiskers.exe -Algorithm SHA256
# compare against the value in Whiskers.exe.sha256
```

## Quick start

See [README.md](README.md) for the full setup. Two EDR paths after the LitterBox install:

- **Elastic Defend** — copy `Config/edr_profiles/elastic.yml.example` → `elastic.yml`, fill in `agent_url` (Whiskers VM), `elastic_url`, and `elastic_apikey`. Optional Whiskers auto-start: `Whiskers.exe --install`.
- **Fibratus (open-source ETW)** — copy `fibratus.yml.example` → `fibratus.yml` with just `agent_url`. On the VM, edit `%PROGRAMFILES%\Fibratus\Config\fibratus.yml` to set `alertsenders.eventlog: {enabled: true, format: json}` and restart the Fibratus service.

---

## Changelog

### Added
- Tailored downloadable report for driver samples (BYOVD section + BYOVD Potential hero)
- `/api/results/<target>/risk` endpoint and matching `grumpycat.get_risk_assessment()` client method
- `GrumpyCats/install_mcp.py` — installer for six MCP clients with auto-detected venv Python
- Command-line arguments input on the dynamic-analysis warning modal (pre-populated from last run)
- RedEdr now captures Microsoft-Windows-Kernel-File / -Network / -Audit-API-Calls / Antimalware-Engine ETW events; new tabs surface File Ops / Network / Audit API / Defender with Process Tree panel and ETW Provider Diagnostics
- Defender threat verdicts at runtime contribute +50 to the Detection Score (only verdicts; scan activity stays descriptive)
- Whiskers — single-binary Rust HTTP agent (`Whiskers/`) for dispatching payloads to a separate EDR-instrumented Windows VM
- Fibratus profile kind (`kind: fibratus` in `Config/edr_profiles/<name>.yml`) — pull-from-event-log alternative to Elastic Defend, matching DetonatorAgent's `FibratusEdrPlugin.cs` integration shape. The operator configures Fibratus on the EDR VM with `alertsenders.eventlog: {enabled: true, format: json}`; rule matches land in the Windows Application event log under `Provider=Fibratus`. Whiskers gains a `GET /api/alerts/fibratus/since?from=…&until=…` endpoint that wevtutil-queries the log for records inside the run window and returns the raw JSON `<Data>` blobs (the agent does no parsing). The new `FibratusEdrAnalyzer` mirrors the Elastic two-phase shape — Phase 1 exec, Phase 2 polls Whiskers — and normalizes Fibratus's actual schema (`events[].proc.{name,exe,cmdline,parent_name,parent_cmdline,ancestors}` + bare `tactic.id`/`technique.id`/`subtechnique.id` labels) into the saved-view renderer's dict shape. No new alert-source coupling on Whiskers beyond one event-log query endpoint.
- Whiskers `--install` / `--uninstall` flags register an `ONLOGON` Windows scheduled task so the agent auto-starts at user logon (no UAC, runs as the invoking user)
- Whiskers `--samples-dir` flag; default drop path is now `<agent-exe-dir>/samples/` (auto-created on first write) instead of `C:\Users\Public\Downloads\`
- Whiskers chunked-XOR write (64 KiB working buffer) — multi-MB payloads finish in milliseconds instead of the 10+ seconds the byte-by-byte loop took, which had been timing out the orchestrator
- Elastic EDR integration via per-profile YAMLs under `Config/edr_profiles/`; each profile gets a "Run with X" tab on the upload page
- Two-phase EDR orchestration: Phase 1 (exec) returns sync, Phase 2 (Elastic alert poll) runs in a background thread and updates the saved JSON when done
- Per-payload alert correlation — query scoped by `host.name` + filename across `file.name`/`process.name`/`file.path`/`process.executable`/`process.command_line`/`process.args` (the `command_line` / `args` clauses pull in alerts on rundll32-launched DLLs, which only carry the DLL name in the parent's command line)
- AV-block detection from Whiskers (`status:"virus"` on Windows errno 225/995/1234) surfaces as `blocked_by_av`
- EDR-kill detection — non-zero exit without an agent-issued kill is labeled "killed by EDR behavior protection". For DLLs, kill classification additionally requires alert evidence (DLL hosts can exit non-zero for benign reasons)
- Per-alert detail panel: Reason, Rule Description, MITRE chips, Triggering API, Memory Region, Call Stack with module provenance, Final User Module, Process / Parent / EDR Response cards
- High/critical EDR alerts contribute up to +50 to the Detection Score (AV blocks +35; multi-profile takes the max)
- New endpoints: `GET /api/edr/profiles`, `GET /api/edr/agents/status`, `GET /api/system/scanners`, `GET /api/results/edr/<target>[/<profile>]`, `GET/POST /analyze/edr/<profile>/<target>`
- New pages: system dashboard at `/` (live scanner availability + EDR agent reachability, polls every minute), `/whiskers` agent inventory, `/analyze/all/<target>` "All" pipeline coordinator, `/results/edr/<profile>/<target>` saved-view (rich detail — MITRE chips, call stack, expandable per-alert detail, raw `_source` — backed by the same renderer as the live scan view)
- "All" analysis mode: client-side coordinator runs Static + every EDR profile in parallel; Dynamic waits only for Static (EDR is on a remote VM, no local resource contention)
- DLL execution support — payloads ending in `.dll` spawn via `rundll32.exe <path>,<entry> [args...]` in both the Whiskers agent and the local Dynamic analyzer; entry point comes from the executable-args field
- GrumpyCats client gained EDR + scanner-health methods (`analyze_edr`, `get_edr_results`, `get_edr_index`, `list_edr_profiles`, `get_edr_agents_status`, `get_scanners_status`, `wait_for_edr_completion`, `fibratus_alerts_since`); CLI subcommands `edr-run` / `edr-results` / `edr-profiles` / `edr-status` / `scanners` / `fibratus-alerts`; matching MCP tools surface the same to LLM clients

### Changed
- Drop-zone moved from `/` to `/upload` (GET); `/` is now the system dashboard. Existing POST `/upload` for file uploads is unchanged.
- URL convention unified — analysis type / qualifier always comes BEFORE the target hash: `/results/<type>/<target>`, `/api/results/<type>/<target>`, `/api/results/edr/<profile>/<target>`. Matches `/analyze/edr/<profile>/<target>`.
- AgentClient gains a separate `exec_timeout` (180s) for the multipart upload + agent-side write path; the cheap endpoints stay at the 10s default.
- Status flow simplified — `blocked_polling_alerts` collapsed into `polling_alerts` plus an orthogonal `summary.blocked_by_av` flag (the polling itself is purely LitterBox→Elastic, so the EDR-VM blocked/clean state shouldn't affect the polling status).
- Sidebar nav: added Dashboard entry; Upload nav points to `/upload`; "Agents" renamed to "Whiskers" (route also at `/whiskers`).
- File-info detection score no longer folds in EDR results (EDR is its own analysis type with its own page; it shouldn't bleed into the static + dynamic + PE score).
- Dashboard `/api/edr/agents/status` is now backed by a 30s TTL cache pre-warmed by a background poller (`services.edr_health`); per-probe timeouts dropped from 4s/5s to 2s. Cold path under 2s, every subsequent dashboard load <5ms (warm cache hit), and the auto-refresh tick stays within cache TTL.
- Whiskers `/api/info` now reports `telemetry_sources: ["fibratus"]` when Fibratus is installed at `C:\Program Files\Fibratus\Bin\fibratus.exe` so the orchestrator can preflight before dispatching to a Fibratus profile.
- Static analyzers (yara + checkplz + stringnalyzer) now run concurrently via a `ThreadPoolExecutor`. Wall time drops from `sum(per-tool)` to `max(per-tool)` — typically ~50% off static analysis (CheckPlz alone is multi-second; yara + stringnalyzer used to add several more after it). Dynamic stays parallel for yara/pe_sieve/moneta/patriot, with hsb running solo afterwards so its sleep-timing measurements aren't perturbed by concurrent process inspection. Per-tool start + finish + wall-time logged.
- `/files` dashboard backed by a per-sample `_summary_cache.json` (`app/services/summary_cache.py`). Each cached entry stamps the source-JSON mtimes; a read recomputes the source mtime set and compares — any drift forces a recompute, so no manual invalidation is needed at any save site. Cache hit short-circuits the 4-6 disk reads + risk recompute the dashboard previously did per-sample. Single-sample render goes from ~16ms cold to ~2ms warm; expected to scale to ~3s cold → ~50ms warm at 200 samples.
- `find_file_by_hash` (`app/utils/path_manager.py`) now keeps a per-folder hash→dirname index validated against the folder's mtime. The 15+ endpoints calling it 2-3× per page load (analysis dispatch, results pages, API readers) share the cache. Cold ≈ 470µs (one listdir), warm ≈ 50µs.
- BYOVD route reads `compile_time` from `file_info.json` instead of re-parsing the PE — saves a redundant `pefile.PE(...)` + `generate_checksum()` round trip on every BYOVD run (multi-second on signed/large drivers).
- Saved EDR view (`edr_info.html` + `edr-saved.js`) drops the inline `{{ edr_results | tojson }}` blob and lazy-fetches the JSON via `/api/results/edr/<profile>/<target>` on `DOMContentLoaded`. HTML shrinks from ~329 KB → ~13 KB on alert-heavy runs; the browser also caches the JSON between reloads.
- EDR alerts table is now diff-aware — fingerprints the alert IDs into `target.dataset.alertsKey` and bails on re-render when unchanged. Detail bodies build lazily on first expand (cached via `data-built`) instead of running `JSON.stringify(a.raw, ...)` for every alert on every poll. Phase-2 polling no longer wipes user-expanded rows.
- EDR Phase-2 client poll picks up adaptive cadence: 2s base, ×1.5 back-off up to 15s on consecutive ticks where `total_alerts` didn't change, reset on movement. Stops on terminal status.
- Dashboard / Whiskers / EDR / All-pipeline poll loops pause on `document.visibilityState === 'hidden'` and resume (with one immediate refresh) on visible. No background-tab traffic.
- Logging unified — single root-level handler with a compact formatter (`HH:MM:SS  LEVEL  module  message`); 5-char fixed-width colored level, dim module name with `app.` / `services.` / `blueprints.` / `analyzers.` prefixes and `_analyzer` suffixes stripped. Werkzeug renamed to `http` and access lines reformatted from `127.0.0.1 - - [date] "GET /path HTTP/1.1" 200 -` to `GET    /path  → 200`. urllib3 / requests muted to WARNING.
- `_classify_kill` (both elastic + fibratus EDR analyzers) requires alert evidence for ALL payloads — non-zero exit alone is no longer sufficient (false positives on payloads that crash on their own; Fibratus is detect-only and can never legitimately trigger this). Frontend DETECTED badge gated on `isTerminal && totalAlerts > 0`; killed_by_edr / blocked_by_av / failure / polling states only influence the detail string, never the badge.
- AgentClient.get_execution_logs caps stdout/stderr at 256 KB. Prevents the saved-view template from inlining a 263 MB stdout (mimikatz spamming the prompt 18M times) and hanging the browser. Saved-view route also truncates defensively at load time so older saved findings render without a re-save.
- /analyze/edr no longer writes a JSON for pre-execution failures (agent_unreachable / busy / error). Pages for samples whose EDR dispatch failed at the transport layer no longer pretend to have results — file-info hero hides per-profile buttons unless the saved JSON actually exists.
- /analyze/all redesign: stat tiles (stages / alerts / elapsed), phase-banded rows, color-coded state pills (QUEUED / RUNNING / COMPLETED / FAILED / SKIPPED), agent-down preflight marks unreachable EDR profiles `SKIPPED` instead of burning the timeout, done banner only links to stages that actually produced data.
- File-info hero buttons fully data-driven — Static / Dynamic / HolyGrail / per-EDR-profile only render if the corresponding saved JSON exists for the sample. A freshly-uploaded sample with no analyses run shows only the Back button.
- Backend split into Flask blueprints, services, and a `utils/` package; subprocess analyzers consolidated under `BaseSubprocessAnalyzer`
- Frontend split into per-tool ES6 modules with shared utils; reusable Jinja macros for scanner tables
- Full UI redesign on a terminal/IDE shell with new `.lb-*` design tokens and JetBrains Mono throughout
- Tailwind upgraded to v4 via the standalone CLI binary (committed `tailwind.min.css` ~10× smaller)
- Self-contained downloadable report — Tailwind CDN dropped, CSS inlined, logo embedded
- Stringnalyzer block in the report now renders every non-empty IOC bucket as a full code block (16 categories, 100-item cap)
- `LitterBoxMCP.py` full rewrite onto modern FastMCP (async tools, stderr logging, `Annotated[..., Field(...)]` params, four focused OPSEC prompts)
- `grumpycat.py` dispatch-table CLI and parallel `get_comprehensive_results`
- UI terminology reframed for operator-first reading: Detection Score, Triggering Indicators, Sensitive Imports, Signature triggered, Critical Imports, Payload Analysis
- Color palette softened across the app — severity tokens shifted -500 → -400, summary risk badges converted from solid bg to outlined chips, heavy rgba alphas tightened
- Analysis-type cards now show explicit `Run X Scan →` CTAs with stronger hover state
- RedEdr launch line is now `--etw --show --with-antimalwareengine --with-defendertrace --trace ...` (replaces broken `-e --trace` which RedEdr's cxxopts schema didn't recognize)
- Payload now fires as soon as RedEdr signals ETW-providers-attached (1-3s typical) instead of a fixed 15s sleep
- Module-load timeline deduplicates PEB-snapshot DLLs against ETW image_loads; kernel device paths stripped to basenames
- ETW timestamps shown as `HH:MM:SS.mmm` (FILETIME → local time) instead of raw 64-bit values
- Defender events split into threat / scan / internal categories; the noise table is collapsed by default with a verdict line summarizing what Defender did
- Upload page analysis selector — stack of cards replaced with a segmented tab strip + per-mode body
- Global font-size bump (10/11/12/13px → 11/12/13/14px)
- Upload pipeline ~4× faster on multi-MB PEs: `Counter`-based entropy, `pefile` fast_load + lazy import parse, single checksum pass

### Fixed
- XSS hardening at user-data interpolation sites in results-page renderers
- Detection counts on `/results/<hash>/static` no longer leak dynamic-scope counts
- Per-tool render failures no longer suppress the rest of the rendering
- Office macro upload no longer throws on missing `macroDetectionNotes` element (upstream issue)
- `LitterBoxMCP.py` startup crash — broken import, removed `mcp.serve(...)` API, and stdout-corrupting logging all fixed
- RedEdr parser was reading PascalCase ETW field names (ProcessID, ImageName, ThreadID, etc.) but RedEdr lowercases all field names; Threads / Images / Child Processes / CPU Priority tabs now populate with real data instead of nulls
- Audit-API events now show `OpenProcess` / `OpenThread` (mapped from `etw_event_id`) instead of the placeholder task name `Info`
- RedEdr is now always cleaned up on dynamic-analysis failure paths (early termination, payload crash, analyzer exception); previously left orphaned subprocesses

### Removed
- Pre-redesign Tailwind utility chains and inline cyber-themed `<style>` blocks
- Tailwind CDN runtime dependency from `report.html`
- Dead code in `grumpycat.py` and `LitterBoxMCP.py` (cache, unused imports, exception envelope, lazy client wrapper)
- `etw_wait_time` config key (replaced by event-driven readiness signal)

### Notes
- New runtime dependency: `requests==2.32.3`
- Whiskers binary not committed — build via `cargo build --release` (see `Whiskers/README.md` → "Building from source")
- No public API / endpoint changes; existing JS DOM-ID contracts preserved
