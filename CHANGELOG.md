# Changelog

All notable changes to this project will be documented in this file.

## [v5.0.0] - 2026-04-28
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
- New endpoints: `GET /api/edr/profiles`, `GET /api/edr/agents/status`, `GET /api/results/edr/<target>[/<profile>]`, `GET/POST /analyze/edr/<profile>/<target>`. `/health` was extended to also return scanner inventory + EDR agent reachability (one-shot status fetch).
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

### Scanners
- New "Scanners" tracking table in README — version + last-updated date + source per scanner/rule pack so operators can tell at a glance whether each binary is current
- PE-Sieve refreshed to 0.4.1.2 (commit `f1dc39d`, 2026-05-02)
- Hollows-Hunter refreshed to 0.4.1.2 (commit `e271f7e`, 2026-04-18)
- Moneta refreshed (commit `5b65395`, 2024-03-16)
- Hunt-Sleeping-Beacons refreshed (commit `84dd3a9`, 2026-01-25)
- RedEdr switched from upstream release binary (0.9, 5.6 MB) to source-built EXE-only (`3bd6b97`, 2026-05-03, 640 KB) — Driver / DLL / PplService projects skipped (`/t:RedEdr`); LitterBox's RedEdr usage is ETW-only so the bundled components weren't needed
- YARA rules restructured under `Scanners/Yara/rules/` into `elastic-yara/` and `YARAForge/` subdirs; orchestrator `LitterBox.yar` regenerated to match the new layout
- Elastic YARA rules synced to upstream `d131ea8` (2026-04-30, 686 rules — 684 upstream + Morpes/Torii retained locally after Elastic rotated them out)
- YARA-Forge bumped to 0.9.1 (release `20260503`, 2026-05-03) — separate `YARAForge_Extended.yar` pack alongside the Elastic rules

### Notes
- New runtime dependency: `requests==2.32.3`
- Whiskers binary not committed — build via `cargo build --release` (see `Whiskers/BUILD.md`)
- No public API / endpoint changes; existing JS DOM-ID contracts preserved


## [v4.1.0] - 2025-09-01
### Changed
- Moved YARA rules: `LitterBox.yar` relocated to scanner directory
- Individual rules now in `.\Rules` subdirectory with updated include paths

### Added
- Clickable header section: Logo and title now navigate to home page


## [v4.1.0] - 2025-09-01
### Added
- Docker deployment support for Linux hosts
- Automated Windows 10 container setup with LitterBox installation
- Web viewer and RDP access for containerized environments
- `--ip` parameter to specify custom host IP address

### Fixed
- Missing page title in doppelganger template


## [v4.0.0] - 2025-08-19
### Added
- HolyGrail BYOVD Hunter analyzer with third-party engine integration
- Driver analysis system with dedicated risk scoring for BYOVD exploitation
- Unified risk calculation backend supporting file, process, and driver analysis
- Driver vs payload separation in summary view and routing
- `/holygrail` endpoint for driver upload and analysis
- `/results/{hash}/byovd` endpoint for driver-specific results viewing
- Collapsible sidebar with smooth animations and state persistence
- Enhanced Python client library with HolyGrail analysis support and comprehensive API coverage
- Comprehensive LNK files parser library

### Changed
- Extended binary detection to support Go and Rust runtime analysis
- Enhanced import analysis to separate runtime imports from suspicious imports  
- Updated UI styling with color coding for different import types
- Enhanced UI to show LNK analysis details when LNK files are uploaded
- Improved risk calculation to exclude runtime binaries from checksum penalties
- Replaced binary flags with runtime type classification system
- Updated analysis pipeline to distinguish drivers vs. payloads.
- 

### Fixed
- Static analysis results scan duration bug


## [v3.3.0] - 2025-08-11
### Fixed
- Corrected PE import hint display for Go binaries
- Reduced false positives in Go binary detection
- Avoided mislabeling unrelated imports as `Go runtime`
- Skipped checksum penalties for Go binaries

### Changed
- Go binary checksums now shown as informational with explanation
- Backend/API updated with `is_go_binary` flag


## [v3.2.0] - 2025-05-29
### Changed
- Major code refactoring for improved efficiency and maintainability
- Eliminated code duplication across routes, utilities, analysis manager, and Python client
- Centralized common functionality with helper classes (RouteHelpers, FileTypeDetector, SecurityAnalyzer, RiskCalculator)
- Enhanced error handling with consistent patterns and unified validation methods
- Restructured AnalysisManager with focused methods and specialized validation
- Refactored Python client removing duplicate implementations and adding helper methods

### Fixed
- Report generation bug for PID-based analysis missing process_output attribute



## [v3.1.0] - 2025-05-22
### Added
- Implemented API endpoints for HTML report generation and retrieval
- Added report generation functionality to Utils class
- Introduced comprehensive HTML report template system
- Extended Python client library with report management capabilities


## [v3.0.1] - 2025-05-16
### Added
- Implemented PE file suspicious import classification using MalApi.io database
- Developed comprehensive analyzer implementation documentation

### Changed
- Enhanced README structure and content
- Improved suspicious import visualization in file upload interface
- Restructured directory organization for better maintainability


## [v3.0.0] - 2025-05-16
### Added
- Python Clients to interact with LitterBox Server 
  	* `grumpycat.py` - Standalone command-line client for direct server interaction
  	* `LitterBoxMCP.py` - MCP server interface for LitterBox Server communication


## [v2.5.2] - 2025-05-09
### Fixed
- Clinet Side: removed hard-coded size limit  
- Removed file-type detection based on extension

### Added
- File-type detection based on magic bytes


## [v2.5.1] - 2025-04-24
### Fixed
- Cleanup method bug fixed FuzzyDB delete
- README Update
- Bug Fixed: size limit

### Changed
- Yara Analyzer support YARA Forge format

### Added
- YARA Forge Extended set


## [v2.5.0] - 2025-02-16
### Added
- New FuzzyHash analyzer (ssdeep)
- FuzzyHash database with open-source tools
- Doppelganger endpoint providing a unified interface for both Blender and FuzzyHash
- New configuration section for Doppelganger
- Application version

### Fixed
- Relocated all Blender code to the Doppelganger section
- Enhanced cleanup method
- Improved folder structure and creation process
- Enhanced error handelig on Blender analyzer client side
- base.html template disaply app version


## [v2.0.0] - 2025-02-08
### Added
- New BlenderAnalyzer implementation with Moneta, HSB, and HollowsHunter integration
- Blender endpoint for system scanning and payload comparison
- New Dynamic Analyzer HollowsHunter

### Fixed
- Scanners output parsing improvements


## [v1.6.1] - 2025-01-27
### Added
- Captured and displayed payload output for better analysis.
- Enhanced the Stringnalyzer scanner with improved functionality.

### Changed
- Summary section now includes Stringnalyzer & Payload output results.
- Improved HTML and JavaScript code for analysis results. 
- Renamed the 'upload' section in the YAML config file to 'util'.

### Fixed
- Resolved missing IOC issue in Moneta.
- Multiple bug fixes in summary section


## [v1.6.0] - 2025-01-26
### Added
- New Static analyzer Stringnalyzer implementation

### Fixed
- Refactoring health check implementation to use configuration file settings


## [v1.5.1] - 2025-01-25
### Added
- Support for executing payloads with custom command-line arguments
- Increased default payload size limit to 100MB
- Configurable payload initialization timeout settings
- New Version for PE-Sieve scanner

### Fixed
- Improved error handling for payloads that terminate before scan completion
- Enhanced UI/UX for clearer error messaging and handling


## [v1.5.0] - 2025-01-11
### Added
- New Dynamic analyzer RedEdr Scanner implementation
- Added LICENSE file

### Changed
- Various code refactoring improvements

### Fixed
- Multiple bug fixes


## [v1.2.1] - 2025-01-06
### Added
- Debug mode enabled
- Small improvements to core functionality


## [v1.2.0] - 2025-01-05
### Added
- API route for results with JSON output (@som3canadian)
- Improved risk calculation system
- Enhanced summary section with better reporting

### Changed
- Documentation improvements
- Updated README with new features and instructions

### Fixed
- Code optimization and cleanup
- Risk calculation refinements


## [v1.0.0] - 2025-01-04
### Added
- Initial release
- Base functionality implementation
- Core scanning features

### Notes
- Repository initialized with basic documentation
