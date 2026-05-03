# GrumpyCats

![GrumpyCats Banner](https://github.com/user-attachments/assets/9d4018f7-79e8-4835-82af-49cf6c12b9e9)

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPL%20v3-green.svg)]()
[![MCP Supported](https://img.shields.io/badge/MCP-Supported-blueviolet.svg)]()
[![AI Powered](https://img.shields.io/badge/AI-Powered-brightgreen.svg)]()

The client side of LitterBox. Three pieces sharing one codebase:

| File | What it is | Wiki |
|---|---|---|
| **`grumpycat.py`** | Command-line client | [GrumpyCats CLI](../../../wiki/GrumpyCats-CLI) |
| **`litterbox_client/`** | Python library (composed mixins) | [GrumpyCats Library](../../../wiki/GrumpyCats-Library) |
| **`LitterBoxMCP.py`** + **`install_mcp.py`** | MCP server + installer (29 tools, 4 OPSEC prompts) | [LitterBoxMCP](../../../wiki/LitterBoxMCP) |

## Install

```bash
pip install requests          # CLI + library
pip install mcp               # additionally for the MCP server
```

## Quick start

**CLI:**
```bash
python grumpycat.py upload payload.exe --analysis static dynamic
python grumpycat.py edr-run <md5> --profile elastic --wait
python grumpycat.py results <md5> --comprehensive
```

**Library:**
```python
from litterbox_client import LitterBoxClient

with LitterBoxClient("http://127.0.0.1:1337") as c:
    info = c.upload_file("payload.exe")
    c.analyze_file(info["md5"], "static", wait_for_completion=True)
    print(c.get_risk_assessment(info["md5"]))
```

**MCP (Claude Desktop / Claude Code / Cursor / Windsurf / VS Code):**
```bash
py install_mcp.py --list                       # see supported clients
py install_mcp.py --install claude-code-project
```

Reload the MCP client after install so the new config is picked up.

## Layout

```
GrumpyCats/
├── grumpycat.py                # CLI entry point
├── cli/                        # argparse parser + command handlers
├── litterbox_client/           # API client, per-domain mixins composed onto _BaseClient
├── LitterBoxMCP.py             # FastMCP wrapper
└── install_mcp.py              # MCP-client config installer
```

Adding a new command = one method in the right mixin under `litterbox_client/`, one subparser in `cli/parser.py`, one handler in `cli/handlers.py`. The MCP tool is one decorator in `LitterBoxMCP.py` since it shares the client.

## Documentation

Full reference for every CLI command, library method, MCP tool, and OPSEC prompt lives in the wiki:

- **[GrumpyCats CLI](../../../wiki/GrumpyCats-CLI)** — every command + flags + examples
- **[GrumpyCats Library](../../../wiki/GrumpyCats-Library)** — mixin structure + every method + batch-fanout example
- **[LitterBoxMCP](../../../wiki/LitterBoxMCP)** — install matrix, all 29 tools, all 4 OPSEC prompts

### Claude Integration

https://github.com/user-attachments/assets/bd5e0653-c4c3-4d89-8651-215b8ee9cea2
