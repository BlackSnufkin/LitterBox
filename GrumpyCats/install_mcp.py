"""Install LitterBox MCP into one or more MCP clients.

Usage:
    py install_mcp.py --list
    py install_mcp.py --install claude-code-project
    py install_mcp.py --install claude-desktop cursor
    py install_mcp.py --install all
    py install_mcp.py --uninstall cursor
    py install_mcp.py --print

The script:
- Picks the project's venv Python (../venv/Scripts/python.exe) when available,
  falling back to $VIRTUAL_ENV, then sys.executable.
- Resolves an absolute path to LitterBoxMCP.py — required because MCP clients
  spawn the server with no inherited CWD.
- Reads any existing client config, merges the LitterBox entry alongside other
  servers (idempotent), and writes back. Never clobbers unrelated entries.
- Verifies `mcp` and `requests` are importable from the chosen Python so the
  server actually has a chance of starting.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Server identity used as the dict key inside each client's "mcpServers" map.
MCP_SERVER_NAME = "litterbox"

SCRIPT_DIR = Path(__file__).parent.resolve()
SERVER_SCRIPT = SCRIPT_DIR / "LitterBoxMCP.py"
REPO_ROOT = SCRIPT_DIR.parent.resolve()


# -----------------------------------------------------------------------------
# Python executable resolution
# -----------------------------------------------------------------------------

def get_python_executable() -> str:
    """Return the absolute path to the Python that should run the MCP server.

    Order of preference:
      1. The repo's bundled venv (../venv) if it exists.
      2. $VIRTUAL_ENV from the current shell.
      3. sys.executable (whatever's running this script).
    """
    candidates: List[Path] = []

    if sys.platform == "win32":
        candidates.append(REPO_ROOT / "venv" / "Scripts" / "python.exe")
    else:
        candidates.append(REPO_ROOT / "venv" / "bin" / "python3")

    venv_env = os.environ.get("VIRTUAL_ENV")
    if venv_env:
        if sys.platform == "win32":
            candidates.append(Path(venv_env) / "Scripts" / "python.exe")
        else:
            candidates.append(Path(venv_env) / "bin" / "python3")

    for c in candidates:
        if c.exists():
            return str(c)
    return sys.executable


def generate_server_entry() -> dict:
    """The dict that goes under <client>.mcpServers.litterbox."""
    return {
        "type": "stdio",
        "command": get_python_executable(),
        "args": [str(SERVER_SCRIPT)],
    }


# -----------------------------------------------------------------------------
# Client registry
# -----------------------------------------------------------------------------
#
# Each client maps to:
#   path:      absolute path to its config JSON
#   structure: list of nested keys leading to the "mcpServers"-equivalent map
#              (e.g. ["servers"] for VS Code, ["mcpServers"] for everyone else)
#   scope:     "project" or "global" — informational, used by --list
#
# Order matters: --install all installs in this order.

def _appdata() -> Path:
    return Path(os.environ.get("APPDATA", "")) if sys.platform == "win32" else Path()


def _claude_desktop_path() -> Path:
    if sys.platform == "win32":
        return _appdata() / "Claude" / "claude_desktop_config.json"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    return Path.home() / ".config" / "Claude" / "claude_desktop_config.json"


def get_clients() -> Dict[str, dict]:
    home = Path.home()
    return {
        "claude-code-project": {
            "path": REPO_ROOT / ".mcp.json",
            "structure": ["mcpServers"],
            "scope": "project",
        },
        "claude-code-global": {
            "path": home / ".claude.json",
            "structure": ["mcpServers"],
            "scope": "global",
        },
        "claude-desktop": {
            "path": _claude_desktop_path(),
            "structure": ["mcpServers"],
            "scope": "global",
        },
        "cursor": {
            "path": home / ".cursor" / "mcp.json",
            "structure": ["mcpServers"],
            "scope": "global",
        },
        "windsurf": {
            "path": home / ".codeium" / "windsurf" / "mcp_config.json",
            "structure": ["mcpServers"],
            "scope": "global",
        },
        "vscode-project": {
            "path": REPO_ROOT / ".vscode" / "mcp.json",
            "structure": ["servers"],   # VS Code project mcp.json uses {"servers": {...}}
            "scope": "project",
        },
    }


def resolve_client_keys(requested: List[str]) -> List[str]:
    """Map user input ("all", aliases, exact keys) to canonical client keys."""
    clients = get_clients()
    if requested == ["all"]:
        return list(clients.keys())

    aliases = {
        "claude-code": "claude-code-project",
        "claude": "claude-desktop",
        "vs-code": "vscode-project",
        "vscode": "vscode-project",
    }
    out: List[str] = []
    for name in requested:
        canonical = aliases.get(name, name)
        if canonical not in clients:
            print(f"Unknown client: {name!r}. Run with --list to see options.", file=sys.stderr)
            sys.exit(1)
        if canonical not in out:
            out.append(canonical)
    return out


# -----------------------------------------------------------------------------
# JSON read / write helpers (idempotent, atomic)
# -----------------------------------------------------------------------------

def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        print(f"ERROR: existing config is invalid JSON: {path}\n  {e}", file=sys.stderr)
        sys.exit(1)


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def walk(config: dict, structure: List[str]) -> dict:
    """Walk into nested keys, creating dicts as needed. Returns the inner map."""
    cur = config
    for key in structure:
        cur = cur.setdefault(key, {})
        if not isinstance(cur, dict):
            raise SystemExit(f"Config has non-dict at {key!r}; refusing to overwrite.")
    return cur


# -----------------------------------------------------------------------------
# Dependency check
# -----------------------------------------------------------------------------

def check_dependencies(python: str) -> List[str]:
    """Return list of importable package names that are missing."""
    missing: List[str] = []
    for pkg in ("mcp", "requests"):
        result = subprocess.run(
            [python, "-c", f"import {pkg}"],
            capture_output=True,
        )
        if result.returncode != 0:
            missing.append(pkg)
    return missing


# -----------------------------------------------------------------------------
# Install / uninstall / list
# -----------------------------------------------------------------------------

def install(client_keys: List[str]) -> None:
    clients = get_clients()
    entry = generate_server_entry()
    python = entry["command"]

    missing = check_dependencies(python)
    if missing:
        print(f"WARNING: {python} is missing: {', '.join(missing)}")
        print(f"  Install with: {python} -m pip install {' '.join(missing)}")
        print()

    for key in client_keys:
        spec = clients[key]
        path: Path = spec["path"]
        config = read_json(path)
        servers = walk(config, spec["structure"])
        servers[MCP_SERVER_NAME] = entry
        write_json(path, config)
        print(f"  Installed {key} -> {path}")

    print()
    print("Restart any running MCP clients for changes to take effect.")


def uninstall(client_keys: List[str]) -> None:
    clients = get_clients()
    for key in client_keys:
        spec = clients[key]
        path: Path = spec["path"]
        if not path.exists():
            print(f"  Skipped {key} (no config at {path})")
            continue
        config = read_json(path)
        try:
            servers = walk(config, spec["structure"])
        except SystemExit:
            continue
        if MCP_SERVER_NAME in servers:
            del servers[MCP_SERVER_NAME]
            write_json(path, config)
            print(f"  Removed {key} from {path}")
        else:
            print(f"  Skipped {key} (not installed)")


def list_clients() -> None:
    python = get_python_executable()
    print(f"Python: {python}")
    print(f"Server: {SERVER_SCRIPT}")
    print()

    missing = check_dependencies(python)
    if missing:
        print(f"WARNING: {python} is missing: {', '.join(missing)}")
        print(f"  Install with: {python} -m pip install {' '.join(missing)}")
        print()

    print("Clients (run with --install <key>):")
    print()
    print(f"  {'KEY':<25} {'SCOPE':<8} {'STATUS':<14} CONFIG PATH")
    print(f"  {'-' * 23:<25} {'-' * 6:<8} {'-' * 12:<14} {'-' * 11}")
    for key, spec in get_clients().items():
        path: Path = spec["path"]
        if path.exists():
            try:
                config = read_json(path)
                cur = config
                for k in spec["structure"]:
                    cur = cur.get(k, {}) if isinstance(cur, dict) else {}
                installed = isinstance(cur, dict) and MCP_SERVER_NAME in cur
                status = "installed" if installed else "config-found"
            except SystemExit:
                status = "invalid-json"
        else:
            status = "config-missing"
        print(f"  {key:<25} {spec['scope']:<8} {status:<14} {path}")


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Install LitterBox MCP into one or more MCP clients.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--list", action="store_true",
        help="List supported clients with detection / install status.",
    )
    g.add_argument(
        "--install", nargs="+", metavar="CLIENT",
        help="Install for one or more clients (or 'all').",
    )
    g.add_argument(
        "--uninstall", nargs="+", metavar="CLIENT",
        help="Uninstall from one or more clients (or 'all').",
    )
    g.add_argument(
        "--print", action="store_true",
        help="Print the MCP config JSON to stdout without writing any files.",
    )
    args = parser.parse_args()

    if args.list:
        list_clients()
    elif args.print:
        print(json.dumps({"mcpServers": {MCP_SERVER_NAME: generate_server_entry()}}, indent=2))
    elif args.install:
        install(resolve_client_keys(args.install))
    elif args.uninstall:
        uninstall(resolve_client_keys(args.uninstall))


if __name__ == "__main__":
    main()
