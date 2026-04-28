# GrumpyCats

![GrumpyCats Banner](https://github.com/user-attachments/assets/9d4018f7-79e8-4835-82af-49cf6c12b9e9)

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPL%20v3-green.svg)]()
[![MCP Supported](https://img.shields.io/badge/MCP-Supported-blueviolet.svg)]()
[![AI Powered](https://img.shields.io/badge/AI-Powered-brightgreen.svg)]()

## What This Is

GrumpyCats is the client side of LitterBox. Three pieces:

1. **`grumpycat.py`** — Python CLI + library for the LitterBox HTTP API.
2. **`LitterBoxMCP.py`** — MCP server that exposes the same surface to AI agents (Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, …) plus four OPSEC-review prompts.
3. **`install_mcp.py`** — one-shot installer that wires `LitterBoxMCP.py` into the right config file for your MCP client of choice.

---

## Table of Contents
- [Command Line Tool](#command-line-tool)
- [Using It](#using-it)
- [Using It as a Library](#using-it-as-a-library)
- [AI Integration (MCP)](#ai-integration-mcp)
- [Installer Reference](#installer-reference)
- [MCP Tools Reference](#mcp-tools-reference)
- [OPSEC Review Prompts](#opsec-review-prompts)

---

## Command Line Tool

The CLI talks to your LitterBox server, handles connection pooling, retries, and structured errors for you.

### Requirements

```bash
pip install requests
```

### Usage

```bash
python grumpycat.py [global-options] <command> [command-options]
```

### Commands

| Command                  | What It Does                                |
|--------------------------|---------------------------------------------|
| `upload`                 | Upload a payload for analysis               |
| `upload-driver`          | Upload a kernel driver for BYOVD analysis   |
| `analyze-pid`            | Analyze a running process                   |
| `results`                | Fetch analysis results                      |
| `report`                 | Generate / view / download an HTML report   |
| `files`                  | List every analyzed payload + summary       |
| `doppelganger-scan`      | Snapshot the host for Blender comparison    |
| `doppelganger-analyze`   | Compare a payload against Blender or fuzzy  |
| `doppelganger-db`        | Build the FuzzyHash baseline DB             |
| `status`                 | Server health + fleet summary               |
| `health`                 | Just the health check                       |
| `cleanup`                | Wipe sandbox artifacts                      |
| `delete`                 | Delete one payload + its results            |

### Global Options

| Option                | What It Does                                       |
|-----------------------|----------------------------------------------------|
| `--debug`             | Verbose logging                                    |
| `--url URL`           | LitterBox server URL (default `http://127.0.0.1:1337`) |
| `--timeout TIMEOUT`   | Request timeout, seconds                           |
| `--no-verify-ssl`     | Skip SSL verification                              |
| `--proxy PROXY`       | Route requests through a proxy                     |

## Using It

### Basics

```bash
# Upload and run static + dynamic
grumpycat.py upload malware.exe --analysis static dynamic

# Upload a kernel driver and immediately run BYOVD
grumpycat.py upload-driver rootkit.sys --holygrail

# Analyze a running process by PID
grumpycat.py analyze-pid 1234 --wait

# Pull every result for a target in one call
grumpycat.py results abc123def --comprehensive

# Or scope to one analysis type
grumpycat.py results abc123def --type static
grumpycat.py results abc123def --type holygrail
```

### Doppelganger / similarity

```bash
# Snapshot the live host for baseline comparison
grumpycat.py doppelganger-scan --type blender

# Score a payload against the FuzzyHash baseline
grumpycat.py doppelganger-analyze abc123def --type fuzzy --threshold 85

# Build the FuzzyHash baseline DB
grumpycat.py doppelganger-db --folder /path/to/refs --extensions .exe .dll
```

### Reports

```bash
# Print to stdout
grumpycat.py report abc123def

# Download to current dir
grumpycat.py report abc123def --download

# Download to a specific dir
grumpycat.py report abc123def --download --output ./reports/

# Open in your browser
grumpycat.py report abc123def --browser
```

### Maintenance

```bash
# Health + fleet summary
grumpycat.py status --full

# Wipe everything
grumpycat.py cleanup --all

# Delete one payload
grumpycat.py delete abc123def
```

---

## Using It as a Library

```python
from grumpycat import LitterBoxClient

with LitterBoxClient(base_url="http://127.0.0.1:1337") as client:
    # Upload and run analysis
    result = client.upload_file("malware.exe")
    file_hash = result["file_info"]["md5"]
    static_result  = client.analyze_file(file_hash, "static")
    dynamic_result = client.analyze_file(file_hash, "dynamic")

    # Pull every result for a target with a single fan-out call
    all_results = client.get_comprehensive_results(file_hash)

    # Driver workflow
    driver_result = client.upload_and_analyze_driver("driver.sys", run_holygrail=True)

    # Risk assessment endpoint
    risk = client.get_risk_assessment(file_hash)
    # → {"risk_score": 32.5, "risk_level": "Medium", "risk_factors": [...]}

    # Doppelganger
    blender_snapshot = client.run_blender_scan()
    comparison       = client.compare_with_blender(file_hash)
    fuzzy_score      = client.analyze_with_fuzzy(file_hash, threshold=85)

    # Server health
    status = client.get_system_status()
```

The client uses a `requests.Session` with retry-on-5xx, fans out the four `/api/results/<hash>/*` reads in parallel for `get_comprehensive_results`, and exposes a context-manager interface so the session closes cleanly.

---

## AI Integration (MCP)

`LitterBoxMCP.py` is a stdio MCP server that exposes 22 tools and 4 OPSEC-review prompts to any MCP-compatible client. Tools run async and offload the sync `LitterBoxClient` calls to a worker thread, so multiple tool calls don't serialize.

### Requirements

```bash
pip install mcp requests
```

The included installer auto-detects the project's `venv/` Python first, then `$VIRTUAL_ENV`, then the `python` running the script — and warns if `mcp` or `requests` are missing so the server actually has a chance of starting after install.

### Quick Install

```bash
# See what clients the installer recognises and which already have litterbox configured
py install_mcp.py --list

# Install for a single client (project-scoped Claude Code config in <repo>/.mcp.json)
py install_mcp.py --install claude-code-project

# Install everywhere
py install_mcp.py --install all
```

After install, **reload your MCP client** (close + reopen Claude Desktop, "Developer: Reload Window" in VS Code, etc.) so the new config is picked up.

### Supported clients

| Key                    | Scope    | Config file                                                    |
|------------------------|----------|----------------------------------------------------------------|
| `claude-code-project`  | project  | `<repo>/.mcp.json`                                             |
| `claude-code-global`   | global   | `~/.claude.json`                                               |
| `claude-desktop`       | global   | `%APPDATA%\Claude\claude_desktop_config.json` (Win) / equivalents on macOS / Linux |
| `cursor`               | global   | `~/.cursor/mcp.json`                                           |
| `windsurf`             | global   | `~/.codeium/windsurf/mcp_config.json`                          |
| `vscode-project`       | project  | `<repo>/.vscode/mcp.json`                                      |

Aliases: `claude-code` → `claude-code-project`, `claude` → `claude-desktop`, `vscode` / `vs-code` → `vscode-project`.

The installer:
- Reads any existing config and merges the LitterBox entry without clobbering other MCP servers you already have.
- Knows that VS Code uses `{"servers": {...}}` while everyone else uses `{"mcpServers": {...}}` and writes the right structure per client.
- Writes atomically (`.tmp` + rename) so a partial write can't corrupt your config.
- Same flags work for `--uninstall`.

### Running the server directly

The installer's job ends after writing the config. The MCP client launches the server as a subprocess. If you want to run it by hand for debugging:

```bash
# stdio transport (default — what MCP clients use)
py LitterBoxMCP.py

# Streamable HTTP transport (for remote clients)
py LitterBoxMCP.py --transport streamable-http --host 127.0.0.1 --port 8765
```

Logs go to stderr — required for stdio transport, since stdout is the JSON-RPC channel.

---

## Installer Reference

`install_mcp.py` modes are mutually exclusive — pick exactly one:

| Flag                              | What It Does                                                                 |
|-----------------------------------|------------------------------------------------------------------------------|
| `--list`                          | Show every supported client + whether LitterBox is currently installed       |
| `--install CLIENT [CLIENT ...]`   | Write the LitterBox entry into one or more clients (or `all`)                |
| `--uninstall CLIENT [CLIENT ...]` | Remove the LitterBox entry from one or more clients (or `all`)               |
| `--print`                         | Dump the config JSON to stdout — for copy-paste into clients we don't ship   |

### Examples

```bash
py install_mcp.py --list
py install_mcp.py --install claude-code-project
py install_mcp.py --install claude-code cursor             # alias + multi-target
py install_mcp.py --install all
py install_mcp.py --uninstall cursor
py install_mcp.py --print                                   # JSON only, no file writes
```

---

## MCP Tools Reference

All 22 tools are async. Tool exceptions become MCP error responses automatically — no manual envelopes.

### Intake — upload + kick off analysis

| Tool                    | What It Does                                                          |
|-------------------------|-----------------------------------------------------------------------|
| `upload_payload`        | Upload an `.exe / .dll / .bin / .lnk / .docx / .xlsx`                 |
| `upload_driver`         | Upload a `.sys` and (by default) immediately run BYOVD                |
| `analyze_static`        | YARA / CheckPlz / Stringnalyzer on an uploaded file                   |
| `analyze_dynamic`       | In-memory YARA, PE-Sieve, Moneta, Patriot, HSB, RedEdr (executes!)    |
| `analyze_holygrail`     | BYOVD analysis on a kernel driver                                     |
| `validate_pid`          | Confirm a PID is accessible before targeting it for dynamic analysis  |

### Retrieval — read the results

| Tool                          | What It Does                                                          |
|-------------------------------|-----------------------------------------------------------------------|
| `get_file_info`               | Metadata: type, size, hashes, entropy, PE structure, suspicious imports |
| `get_static_results`          | YARA + CheckPlz + Stringnalyzer findings                              |
| `get_dynamic_results`         | Memory scanners + behavioral telemetry + process output               |
| `get_holygrail_results`       | LOLDrivers + block status + critical imports                          |
| `get_risk_assessment`         | `{score, level, factors}` for the target                              |
| `get_comprehensive_results`   | All four results in one parallel call                                 |
| `get_report`                  | Full HTML report inline                                               |
| `download_report`             | Save the HTML report to disk and return the path                      |

### Doppelganger — comparison

| Tool                       | What It Does                                                           |
|----------------------------|------------------------------------------------------------------------|
| `run_blender_scan`         | Snapshot the live host                                                 |
| `compare_with_blender`     | Compare a payload's runtime indicators against the host snapshot       |
| `analyze_fuzzy_similarity` | ssdeep similarity score (0-100) against the FuzzyHash baseline         |
| `create_fuzzy_database`    | (Re)build the FuzzyHash baseline DB from a folder of reference binaries|

### Fleet management

| Tool                | What It Does                                                          |
|---------------------|-----------------------------------------------------------------------|
| `list_payloads`     | List every analyzed payload + driver + process with risk summary      |
| `sandbox_status`    | Health + tool readiness + fleet summary                               |
| `cleanup_sandbox`   | Wipe artifacts (destructive — confirm before calling)                 |
| `delete_payload`    | Delete one payload + its results (destructive)                        |

---

## OPSEC Review Prompts

Short, data-first prompt templates. Each one tells the LLM which tools to call and asks targeted questions instead of dumping a wall of categories. All take a `file_hash` parameter.

| Prompt                      | Use For                                                                |
|-----------------------------|------------------------------------------------------------------------|
| `detection_summary`         | "What triggered detection?" — YARA matches, memory anomalies, behavioral telemetry, static red flags |
| `evasion_recommendations`   | "How do I make this stealthier?" — concrete changes per detection, ranked by impact |
| `attribution_check`         | "What gives me away?" — tool similarity, framework fingerprints, compilation artifacts |
| `deployment_readiness`      | "Should I ship this?" — GO / CONDITIONAL / NO-GO verdict against pass-fail criteria |

### Claude Integration

https://github.com/user-attachments/assets/bd5e0653-c4c3-4d89-8651-215b8ee9cea2
