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
- Elastic EDR integration via per-profile YAMLs under `Config/edr_profiles/`; each profile gets a "Run with X" tab on the upload page
- Two-phase EDR orchestration: Phase 1 (exec) returns sync, Phase 2 (Elastic alert poll) runs in a background thread and updates the saved JSON when done
- Per-payload alert correlation — query scoped by `host.name` + filename across `file.name`/`process.name`/`file.path`/`process.executable`
- AV-block detection from Whiskers (`status:"virus"` on Windows errno 225/995/1234) surfaces as `blocked_by_av`
- EDR-kill detection — non-zero exit without an agent-issued kill is labeled "killed by EDR behavior protection"
- Per-alert detail panel: Reason, Rule Description, MITRE chips, Triggering API, Memory Region, Call Stack with module provenance, Final User Module, Process / Parent / EDR Response cards
- High/critical EDR alerts contribute up to +50 to the Detection Score (AV blocks +35; multi-profile takes the max)
- New endpoints: `GET /api/edr/profiles`, `GET /api/results/<hash>/edr[/<profile>]`, `GET/POST /analyze/edr/<profile>/<hash>`

### Changed
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
