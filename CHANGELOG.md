# Changelog

All notable changes to this project will be documented in this file.

## [v4.2.0] - 2026-04-27
### Changed
- **Backend modularised.**
  - `app/routes.py` (1,389 lines) split into 6 Flask blueprints under
    `app/blueprints/` (upload, analysis, results, doppelganger, management,
    api), plus service modules under `app/services/` (rendering, summary,
    tool_check, error_handling) and shared `RouteHelpers` in `app/helpers.py`.
  - `app/__init__.py` now wires `AnalysisManager` and `RouteHelpers` into
    `app.extensions['litterbox']` for blueprint use.
  - `app/utils.py` (1,400 lines) split into the `app/utils/` package with
    single-concern modules: `file_io`, `validators`, `path_manager`,
    `risk_analyzer`, `forensics`, `json_helpers`, `reporting`. Every caller
    migrated; no shim/facade.
  - Extracted `BaseSubprocessAnalyzer` template-method base class in
    `app/analyzers/base.py`. The 9 subprocess-based analyzers (yara/checkplz/
    stringnalyzer static; yara/pe_sieve/moneta/patriot/hsb/hollows_hunter
    dynamic) are now thin subclasses that declare config + implement
    `_parse_output`, eliminating ~40% of duplicated boilerplate.

- **Frontend modularised (no build step added).**
  - The four large monolithic JS files split into per-concern ES6 modules:
    - `results.js` (2,060) → `app/static/js/results/{core,managers,tools,renderers}.js`
    - `holygrail.js` (1,025) → `app/static/js/holygrail/{core,utils}.js`
    - `byovd_info.js` (1,069) → `app/static/js/byovd/{core,api,utils}.js`
    - `upload.js` (974) → `app/static/js/upload/{core,lnk}.js`
  - New `app/static/js/utils/` package with shared helpers: `escape`,
    `formatters`, `severity`, `fetch`, `modals`, `dom`. Single source of
    truth for `escapeHtml`, `formatBytes`, severity-color mapping, etc.
  - Every JS file now loads as `<script type="module">`. `window.X = ...`
    assignments preserved at the bottom of each module so inline
    `onclick="..."` handlers in templates keep resolving.

- **Templates de-duplicated.**
  - New `app/templates/partials/_macros.html` with reusable Jinja macros:
    `scanner_table_header`, `scanner_yara_row`, `scanner_status_cell`,
    `scanner_count_cell`, `status_grid_3`. `static_info.html` and
    `dynamic_info.html` migrated.

- **UI design system & visual unification.** The app previously had two
  disjoint visual identities (purple/cyan cyber-themed `holygrail.html`
  and `byovd_info.html` vs the calmer red-on-dark utilitarian look used
  everywhere else). Pulled everything onto a single design language:
  - New `:root` design tokens in `app/static/css/style.css`: brand
    accents, semantic severity colors (critical/high/medium/low/clean),
    surfaces, borders, text shades, radii, shadows, and severe-state
    glow shadows. Plus a curated `.lb-*` component class catalog
    (cards, buttons, badges, section headers, hash display, empty
    state, animated grid backdrop, critical-state pulse) used as the
    shared vocabulary by every page.
  - `holygrail.html` lost ~437 lines of inline `<style>` (567 → 130);
    `byovd_info.html` lost ~95 lines (164 → 70). The remaining
    page-specific blocks (stepper, upload-zone, console-log, score
    display, loading skeleton) were rewritten using design tokens.
    The `cyber-card` / `cyber-chip` / `cyber-button` / `verdict-holy`
    / `verdict-neutral` classes are gone — every site now uses
    `lb-card{,-elevated,-critical,-high}`, `lb-btn-{primary,secondary,ghost}`,
    `lb-badge-{critical,high,medium,low,clean,info}`. The cyber-glow
    accent is retained but applied only on critical/severe states
    (verdicts, high-severity badges) instead of as page-wide noise.
  - `file_info.html`, `summary.html`, `results.html`, `dynamic_info.html`,
    `static_info.html`, `doppelganger.html`, `error.html`, `upload.html`
    swept to use the component classes; the 4-way Jinja risk-level
    conditional in `file_info.html` collapsed into a single
    `lb-badge-{{ risk_level|lower }}` lookup.
  - Bug fix: duplicate `.logo-wrapper` definition in `style.css` (the
    selector was defined twice with overlapping properties) merged
    into a single rule.

- **Fully self-contained downloadable report.** `report.html` was
  rewritten by hand. Previously the report depended on
  `https://cdn.tailwindcss.com` for runtime utility compilation,
  which left the file partially-broken when downloaded and opened
  from disk without internet. The new template:
  - Drops the CDN dependency. All CSS is inlined in a single
    `<style>` block in `<head>` — design tokens, component classes,
    and only the layout rules the report itself needs.
  - Drops the inline `tailwind.config` script.
  - No `<script>` tags anywhere in the document.
  - Restyled with deliberate typography (system font stack with
    JetBrains Mono for monospace data), tabular-numeric scores,
    restrained pill badges, generous whitespace, severity-coded
    detection chips, per-scanner blocks with locked-size status
    icons (the previous version had a broken-CSS path that rendered
    a giant green checkmark on clean scans), and a dedicated print
    media query.
  - The LitterBox logo is now embedded as a base64 data URI in the
    brand strip (matching the original behaviour), so the
    downloaded file shows the logo offline without an external image
    fetch.
  - Output is ~21 KB for a clean-scan report (no logo) / ~87 KB with
    logo embedded — small enough to email or attach.

### Fixed
- **XSS hardening** at user-data interpolation sites in the results-page
  renderers. `str.data` (binary string content from analysed files),
  `scanResults.hex_dump`, `scan_info.target`, YARA `match.rule`, and the
  shared `renderSection` list-item renderer (which feeds Stringnalyzer
  outputs — URLs, paths, IPs, suspicious strings) now all run through
  `escapeHtml` before insertion via `innerHTML`. Previously these were
  template-literal interpolations that would have rendered any HTML
  content from analysed binaries directly into the operator's DOM.
- **Drag-and-drop upload visual feedback.** `.drag-over` in `style.css`
  used `@apply border-red-500 bg-red-500/5`, but the project uses a
  precompiled Tailwind build with no `@apply` processor — those two
  utilities were silently ignored, leaving only the slight scale-up.
  Replaced with raw CSS equivalent so the red border and tinted
  background actually appear when dragging files over the drop zone.
- **Latent reference bugs in `/files` and `/results/<hash>/info`** that
  passed a removed `utils` parameter through helper chains. Surfaced
  during the routes split; cleaned in `app/services/{rendering,summary}.py`.
- `.gitignore` `Results/` pattern was unanchored and shadowed the new
  `app/static/js/results/` module directory + `app/blueprints/results.py`.
  All path patterns are now anchored to the repo root with leading `/`.
  Also added `/Scanners/PE-Sieve/process_*/` to ignore runtime scan
  artifacts.

### Notes
- No new dependencies. Setup story is unchanged:
  `pip install -r requirements.txt && py litterbox.py --debug` (admin).
- No public API or endpoint URL changes — every previously-working
  request and JSON response shape is preserved.
- Tailwind stays at the precompiled v2.2.19 build. Tailwind purging /
  config / v3 features remain out of scope to keep the deploy
  Python-only. See `CLAUDE.md` for the full rationale.


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
