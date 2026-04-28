# Changelog

All notable changes to this project will be documented in this file.

## [v5.0.0] - 2026-04-28
### Changed
- Backend split into 6 Flask blueprints + services + helpers under `app/blueprints/`, `app/services/`, `app/helpers.py`
- `app/utils.py` (1,400 lines) split into the `app/utils/` package with single-concern modules
- Extracted `BaseSubprocessAnalyzer` template-method base — 9 subprocess analyzers reduced to thin subclasses
- Frontend split into per-concern ES6 modules under `results/`, `holygrail/`, `byovd/`, `upload/`
- Shared JS utils package `app/static/js/utils/` (escape, formatters, severity, fetch, modals, dom)
- Per-tool scanner modules under `app/static/js/results/tools/` — one file per scanner, `tools.js` is now a 66-line registry
- Reusable Jinja macros in `app/templates/partials/_macros.html` consumed by static/dynamic info pages
- Full UI redesign on a terminal/IDE shell — breadcrumb titlebar, iconed sidebar, optional tab row, IDE-style status bar
- New `:root` design tokens and `.lb-*` component vocabulary (panels, tags, buttons, chips, tables, hash rows, empty states)
- JetBrains Mono throughout
- Calm-red rule — bright red reserved for severity tags, destructive buttons, brand dot, and the critical-state statusbar
- Self-contained downloadable report — Tailwind CDN dependency dropped, all CSS inlined, logo embedded as base64
- `CLAUDE.md` primer with an end-to-end "Adding a new scanner tool" recipe (backend + frontend)

### Fixed
- XSS hardening at user-data interpolation sites in results-page renderers
- `ModalHandler` crash on dynamic results pages (null-deref against removed `.bg-gray-900` selector)
- `AnalysisCore.updateStageToComplete` null-deref against removed stage-indicator markup
- Per-tool render failures no longer suppress the rest of the rendering
- Drag-and-drop highlight no longer null-derefs against the removed `.upload-icon` selector
- Upload "Unsupported file type" false positive — extensions now sourced from `window.serverConfig`
- Status-icon styling clash on initial render
- Latent `utils` parameter bugs in `/files` and `/results/<hash>/info` helper chains
- `.gitignore` `Results/` pattern was unanchored and shadowed `app/static/js/results/` and `app/blueprints/results.py`
- Duplicate `.logo-wrapper` definition in `style.css` merged

### Removed
- Pre-redesign Tailwind utility chains across all templates
- Inline cyber-themed `<style>` blocks in `holygrail.html` and `byovd_info.html`
- `_design_previews/` iteration HTML files
- Tailwind CDN runtime dependency from `report.html`

### Notes
- No new dependencies; setup unchanged: `pip install -r requirements.txt && py litterbox.py --debug` (admin)
- Tailwind stays at the precompiled v2.2.19 build
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
