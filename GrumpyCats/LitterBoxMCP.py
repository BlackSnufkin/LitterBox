"""LitterBox MCP server.

Exposes the LitterBox malware-analysis sandbox to MCP clients (Claude Desktop,
Cursor, etc.) so an LLM can drive uploads, analysis, result retrieval, and
report generation, plus a small set of OPSEC-review prompts.

Defaults to stdio transport (which is what Claude Desktop and most local
clients use). For a remote MCP server, run with `--transport streamable-http`.
"""
import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Annotated, List, Optional

# Make the sibling grumpycat module importable regardless of CWD.
sys.path.insert(0, str(Path(__file__).parent))

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from grumpycat import LitterBoxClient

# CRITICAL: stdio transport speaks JSON-RPC over stdout. Logs MUST go to
# stderr or they corrupt the protocol stream and break the connection.
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("litterbox-mcp")

mcp = FastMCP(
    name="LitterBox",
    instructions=(
        "Tools for the LitterBox malware-analysis sandbox: upload payloads / drivers, "
        "run static or dynamic analysis, retrieve results, and generate reports. "
        "Use the prompts for OPSEC review of analysis output. "
        "Tool exceptions are surfaced to the client by FastMCP automatically — "
        "do not wrap returns in success / error envelopes."
    ),
)

# One client for the lifetime of the server. The grumpycat client maintains
# its own connection pool via requests.Session.
client = LitterBoxClient(base_url="http://127.0.0.1:1337", logger=logger)


async def _call(fn, *args, **kwargs):
    """Run a sync grumpycat call in a worker thread without blocking the event loop."""
    return await asyncio.to_thread(fn, *args, **kwargs)


# =============================================================================
# Intake — upload files and kick off analysis
# =============================================================================

@mcp.tool()
async def upload_payload(
    path: Annotated[str, Field(description="Local path to the payload file (visible to the LitterBox server's filesystem).")],
    name: Annotated[Optional[str], Field(description="Optional override for the uploaded filename.")] = None,
) -> dict:
    """Upload a payload (.exe / .dll / .bin / .lnk / .docx / .xlsx) for later analysis.

    Returns the file's MD5 hash and basic metadata. Use the hash with the
    `analyze_*` and `get_*` tools.
    """
    return await _call(client.upload_file, path, file_name=name)


@mcp.tool()
async def upload_driver(
    path: Annotated[str, Field(description="Local path to a .sys kernel driver.")],
    name: Annotated[Optional[str], Field(description="Optional override for the uploaded filename.")] = None,
    run_holygrail: Annotated[bool, Field(description="Run HolyGrail BYOVD analysis right after upload.")] = True,
) -> dict:
    """Upload a kernel driver and (by default) immediately run BYOVD analysis."""
    return await _call(
        client.upload_and_analyze_driver, path, file_name=name, run_holygrail=run_holygrail
    )


@mcp.tool()
async def analyze_static(
    file_hash: Annotated[str, Field(description="MD5 hash returned by an earlier upload.")],
    wait: Annotated[bool, Field(description="Block until the scan finishes (recommended).")] = True,
) -> dict:
    """Run static analysis on an uploaded file (YARA / CheckPlz / Stringnalyzer)."""
    return await _call(client.analyze_file, file_hash, "static", wait_for_completion=wait)


@mcp.tool()
async def analyze_dynamic(
    target: Annotated[str, Field(description="MD5 hash of an uploaded file OR a numeric PID for a running process.")],
    cmd_args: Annotated[Optional[List[str]], Field(description="Command-line arguments passed to the payload.")] = None,
    wait: Annotated[bool, Field(description="Block until the scan finishes (recommended).")] = True,
) -> dict:
    """Run dynamic analysis (in-memory YARA, PE-Sieve, Moneta, Patriot, HSB, RedEdr).

    Note: dynamic analysis EXECUTES the payload. Confirm with the user first.
    """
    return await _call(
        client.analyze_file, target, "dynamic", cmd_args=cmd_args, wait_for_completion=wait
    )


@mcp.tool()
async def analyze_holygrail(
    file_hash: Annotated[str, Field(description="MD5 of an uploaded .sys driver.")],
    wait: Annotated[bool, Field(description="Block until the scan finishes (recommended).")] = True,
) -> dict:
    """Run HolyGrail BYOVD analysis on a kernel driver."""
    return await _call(client.analyze_holygrail, file_hash, wait_for_completion=wait)


@mcp.tool()
async def validate_pid(
    pid: Annotated[int, Field(description="OS-level process ID.")],
) -> dict:
    """Confirm a PID exists and is accessible before targeting it for dynamic analysis."""
    return await _call(client.validate_process, pid)


# =============================================================================
# Retrieval — fetch analysis results and reports
# =============================================================================

@mcp.tool()
async def get_file_info(file_hash: str) -> dict:
    """File metadata: type, size, hashes, entropy, PE structure, suspicious imports."""
    return await _call(client.get_file_info, file_hash)


@mcp.tool()
async def get_static_results(file_hash: str) -> dict:
    """Static analysis output (YARA matches, CheckPlz findings, Stringnalyzer indicators)."""
    return await _call(client.get_static_results, file_hash)


@mcp.tool()
async def get_dynamic_results(target: str) -> dict:
    """Dynamic analysis output (memory scanners, behavioral telemetry, process output)."""
    return await _call(client.get_dynamic_results, target)


@mcp.tool()
async def get_holygrail_results(file_hash: str) -> dict:
    """HolyGrail BYOVD output for a driver (LOLDrivers / block status / critical imports)."""
    return await _call(client.get_holygrail_results, file_hash)


@mcp.tool()
async def get_risk_assessment(target: str) -> dict:
    """Computed risk: numerical score, level (Low / Medium / High / Critical), contributing factors."""
    return await _call(client.get_risk_assessment, target)


@mcp.tool()
async def get_comprehensive_results(target: str) -> dict:
    """All available results in one parallel call (file_info + static + dynamic + holygrail)."""
    return await _call(client.get_comprehensive_results, target)


@mcp.tool()
async def get_report(target: str) -> str:
    """Render the full HTML analysis report and return it inline as a string."""
    return await _call(client.get_report, target)


@mcp.tool()
async def download_report(
    target: str,
    output_path: Annotated[Optional[str], Field(description="Directory or full path to save the .html. Defaults to current directory.")] = None,
) -> dict:
    """Download the HTML report to disk and return the saved path."""
    saved = await _call(client.download_report, target, output_path)
    return {"saved_to": saved}


# =============================================================================
# Doppelganger — comparison against host snapshot or fuzzy-hash baseline
# =============================================================================

@mcp.tool()
async def run_blender_scan() -> dict:
    """Snapshot the live host so Blender can compare payload runtime indicators against it."""
    return await _call(client.run_blender_scan)


@mcp.tool()
async def compare_with_blender(file_hash: str) -> dict:
    """Compare a payload's runtime indicators against the host snapshot."""
    return await _call(client.compare_with_blender, file_hash)


@mcp.tool()
async def analyze_fuzzy_similarity(
    file_hash: str,
    threshold: Annotated[int, Field(description="ssdeep similarity cutoff 0-100.", ge=0, le=100)] = 85,
) -> dict:
    """Score a payload's similarity to known offensive tools via fuzzy hashing."""
    return await _call(client.analyze_with_fuzzy, file_hash, threshold)


@mcp.tool()
async def create_fuzzy_database(
    folder_path: Annotated[str, Field(description="Directory of known-tool binaries to fingerprint.")],
    extensions: Annotated[Optional[List[str]], Field(description="File extensions to include (e.g. ['.exe', '.dll']).")] = None,
) -> dict:
    """(Re)build the FuzzyHash baseline DB from a folder of reference binaries."""
    return await _call(client.create_fuzzy_database, folder_path, extensions)


# =============================================================================
# Fleet — list / status / cleanup
# =============================================================================

@mcp.tool()
async def list_payloads() -> dict:
    """List every analyzed payload, driver, and process in the sandbox with risk summary."""
    return await _call(client.get_files_summary)


@mcp.tool()
async def sandbox_status() -> dict:
    """Health, tool readiness, and fleet summary for the LitterBox server."""
    return await _call(client.get_system_status)


@mcp.tool()
async def cleanup_sandbox(
    include_uploads: bool = True,
    include_results: bool = True,
    include_analysis: bool = True,
) -> dict:
    """Wipe analysis artifacts. DESTRUCTIVE — confirm with the user before calling."""
    return await _call(
        client.cleanup,
        include_uploads=include_uploads,
        include_results=include_results,
        include_analysis=include_analysis,
    )


@mcp.tool()
async def delete_payload(file_hash: str) -> dict:
    """Delete one payload and its results. DESTRUCTIVE — confirm with the user before calling."""
    return await _call(client.delete_file, file_hash)


# =============================================================================
# Prompts — OPSEC review templates
# Short, focused, data-first. Each prompt tells the LLM which tools to call,
# then asks targeted questions instead of dumping a wall of categories.
# =============================================================================

@mcp.prompt()
def detection_summary(file_hash: str) -> str:
    """Summarize what triggered detection in the analysis."""
    return f"""Load `get_comprehensive_results("{file_hash}")` and summarize:

1. **YARA matches** — for each rule that fired, name it and the string / pattern that triggered it.
2. **Memory anomalies** — for each PE-Sieve / Moneta / Patriot / HSB finding, identify the technique it maps to (e.g. private RWX → manual injection, modified PE header → unhooking).
3. **Behavioral telemetry** — flag anything in the RedEdr timeline atypical for a benign process (suspicious DLL loads, child processes, IOCTL traffic).
4. **Static red flags** — entropy, packing, suspicious imports, attribution-bearing strings.

Be specific: cite rule names, region addresses, API names. Do not speculate beyond the data.
"""


@mcp.prompt()
def evasion_recommendations(file_hash: str) -> str:
    """Suggest concrete evasion improvements based on what the sandbox detected."""
    return f"""Use `get_comprehensive_results("{file_hash}")` to read the detection output, then propose specific changes that would reduce each detection.

For each recommendation:
- **What was detected** — one line, citing the actual finding.
- **Why it triggers** — the underlying technique or signal.
- **Concrete change** — actionable (e.g. "encrypt the C2 URL string and decrypt at use site"), not generic ("obfuscate strings").
- **Trade-off** — operational cost or downside.

Order by detection impact, highest first. Skip generic advice.
"""


@mcp.prompt()
def attribution_check(file_hash: str) -> str:
    """Identify tool / framework attribution risk."""
    return f"""Pull `analyze_fuzzy_similarity("{file_hash}")` and `compare_with_blender("{file_hash}")`, then assess:

1. **Tool similarity** — which known offensive tools is this closest to? Score + name.
2. **Framework fingerprints** — Cobalt Strike / Sliver / Havoc / Metasploit-style indicators in strings, behaviors, or memory artifacts.
3. **Compilation artifacts** — RDIs, build paths, debug info that ties this binary to a specific developer or environment.

Output 3-5 attribution vectors ranked by confidence, plus one mitigation per vector.
"""


@mcp.prompt()
def deployment_readiness(file_hash: str) -> str:
    """Go / Conditional / No-Go decision based on detection state."""
    return f"""Read `get_comprehensive_results("{file_hash}")` and `get_risk_assessment("{file_hash}")`.

Render a single-line verdict: **GO** / **CONDITIONAL** / **NO-GO**.

Then for each of these criteria, state PASS / FAIL with a one-sentence reason cited from the data:
- Zero YARA matches.
- No memory anomalies (private RWX, modified PE headers, threads in non-image memory).
- Risk score below 40.
- No high-confidence attribution (fuzzy similarity < 70 to known tools).

If anything fails, list the specific blockers and what would have to change to convert each to a pass.
"""


# =============================================================================
# Entry point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="LitterBox MCP server.")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="MCP transport. 'stdio' for Claude Desktop / Cursor (default); "
             "'streamable-http' for a remote MCP server.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address for streamable-http (default 127.0.0.1; only set 0.0.0.0 deliberately).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port for streamable-http (default 8765).",
    )
    args = parser.parse_args()

    if args.transport == "stdio":
        logger.info("Starting LitterBox MCP on stdio")
        mcp.run(transport="stdio")
    else:
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        logger.info("Starting LitterBox MCP on http://%s:%d/mcp", args.host, args.port)
        mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
