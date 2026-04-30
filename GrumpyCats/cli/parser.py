"""argparse parser for `grumpycat` + the helper that wires CLI args
into a configured `LitterBoxClient`.

Subcommand definitions are grouped by domain via comment headers so the
parser stays readable as the surface grows.
"""

import argparse
import logging

from litterbox_client import LitterBoxClient


def build_parser() -> argparse.ArgumentParser:
    """Build the full CLI parser including every subcommand."""
    parser = argparse.ArgumentParser(
        description="LitterBox Payload-Analysis Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )

    # Global options apply to every subcommand.
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--url", default="http://127.0.0.1:1337", help="LitterBox server URL")
    parser.add_argument("--timeout", type=int, default=120, help="Request timeout in seconds")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://proxy:8080)")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    _add_intake(subparsers)
    _add_results(subparsers)
    _add_edr(subparsers)
    _add_doppelganger(subparsers)
    _add_reports(subparsers)
    _add_system(subparsers)

    return parser


def setup_client(args) -> LitterBoxClient:
    """Build a `LitterBoxClient` from parsed CLI args."""
    client_kwargs = {
        "base_url": args.url,
        "timeout": args.timeout,
        "verify_ssl": not args.no_verify_ssl,
        "logger": logging.getLogger("litterbox"),
    }
    if args.proxy:
        client_kwargs["proxy_config"] = {"http": args.proxy, "https": args.proxy}
    return LitterBoxClient(**client_kwargs)


# =============================================================================
# Subcommand groups — one private helper per domain so build_parser() stays
# easy to scan top-down.
# =============================================================================


def _add_intake(subparsers):
    """upload, upload-driver, analyze-pid, delete."""
    upload = subparsers.add_parser("upload", help="Upload file for analysis")
    upload.add_argument("file", help="File to upload")
    upload.add_argument("--name", help="Custom name for the file")
    upload.add_argument(
        "--analysis", nargs="+", choices=["static", "dynamic"],
        help="Run analysis after upload",
    )
    upload.add_argument("--args", nargs="+", help="Command line arguments for dynamic analysis")

    driver = subparsers.add_parser("upload-driver", help="Upload kernel driver")
    driver.add_argument("file", help="Driver file to upload")
    driver.add_argument("--name", help="Custom name for the driver")
    driver.add_argument("--holygrail", action="store_true", help="Run HolyGrail analysis")

    apid = subparsers.add_parser("analyze-pid", help="Analyze running process")
    apid.add_argument("pid", type=int, help="Process ID to analyze")
    apid.add_argument("--wait", action="store_true", help="Wait for analysis completion")
    apid.add_argument("--args", nargs="+", help="Command line arguments")

    dl = subparsers.add_parser("delete", help="Delete file and its results")
    dl.add_argument("hash", help="File hash to delete")


def _add_results(subparsers):
    """results."""
    res = subparsers.add_parser("results", help="Get analysis results")
    res.add_argument("target", help="File hash or PID")
    res.add_argument(
        "--type", choices=["static", "dynamic", "info", "holygrail"],
        help="Type of results to retrieve",
    )
    res.add_argument(
        "--comprehensive", action="store_true",
        help="Get all available results in parallel",
    )


def _add_edr(subparsers):
    """edr-run, edr-results, edr-profiles, edr-status, scanners, fibratus-alerts."""
    run = subparsers.add_parser(
        "edr-run", help="Dispatch a payload to an EDR profile (Whiskers + Elastic / Fibratus)",
    )
    run.add_argument("hash", help="File hash returned by upload")
    run.add_argument("--profile", required=True, help="EDR profile name (Config/edr_profiles/<name>.yml)")
    run.add_argument("--args", nargs="+", help="Command-line arguments passed to the payload")
    run.add_argument("--xor-key", type=int, help="Single byte (0-255) used to XOR-encode the payload in transit")
    run.add_argument("--wait", action="store_true", help="Poll until Phase-2 settles")
    run.add_argument("--timeout", type=float, default=180.0, help="Phase-2 wait timeout in seconds (default 180)")

    edrres = subparsers.add_parser("edr-results", help="Read saved EDR findings for a target")
    edrres.add_argument("hash", help="File hash")
    edrres.add_argument("--profile", help="Specific profile (omit for the cross-profile index)")

    subparsers.add_parser("edr-profiles", help="List registered EDR profiles")
    subparsers.add_parser("edr-status", help="Live probe of every EDR profile (Whiskers + backend reachability)")
    subparsers.add_parser("scanners", help="Inventory of configured local analyzers and whether their binaries exist")

    # Fibratus testing helper — wire-check the agent's event-log query
    # path without running a payload. Useful right after Fibratus is set
    # up on a new VM to confirm `format: json` + rule matches reach us.
    fib = subparsers.add_parser(
        "fibratus-alerts",
        help="Test/debug: pull Fibratus alerts via Whiskers for a registered profile (no exec)",
    )
    fib.add_argument("--profile", required=True, help="Fibratus profile name (kind=fibratus)")
    fib.add_argument(
        "--from", dest="since", required=True,
        help="ISO8601 lower bound (UTC), e.g. 2026-04-30T00:00:00Z",
    )
    fib.add_argument("--until", dest="until", help="ISO8601 upper bound (UTC); defaults to now")


def _add_doppelganger(subparsers):
    """doppelganger-scan / -analyze / -db."""
    scan = subparsers.add_parser("doppelganger-scan", help="Run doppelganger scan")
    scan.add_argument(
        "--type", choices=["blender"], default="blender",
        help="Type of scan to perform",
    )

    ana = subparsers.add_parser("doppelganger-analyze", help="Doppelganger analysis")
    ana.add_argument("hash", help="File hash to analyze")
    ana.add_argument(
        "--type", choices=["blender", "fuzzy"], required=True,
        help="Type of analysis",
    )
    ana.add_argument(
        "--threshold", type=int, default=1,
        help="Similarity threshold for fuzzy analysis",
    )

    db = subparsers.add_parser("doppelganger-db", help="Create doppelganger database")
    db.add_argument("--folder", required=True, help="Folder path to process")
    db.add_argument("--extensions", nargs="+", help="File extensions to include")


def _add_reports(subparsers):
    """report."""
    rpt = subparsers.add_parser("report", help="Generate analysis report")
    rpt.add_argument("target", help="File hash or process ID")
    rpt.add_argument("--download", action="store_true", help="Download the report")
    rpt.add_argument("--output", help="Output path for downloaded report")
    rpt.add_argument("--browser", action="store_true", help="Open report in browser")


def _add_system(subparsers):
    """status, health, files, cleanup."""
    status = subparsers.add_parser("status", help="Get system status")
    status.add_argument("--full", action="store_true", help="Get comprehensive status")

    subparsers.add_parser("health", help="Check service health")
    subparsers.add_parser("files", help="Get summary of all analyzed files")

    cu = subparsers.add_parser("cleanup", help="Clean up analysis artifacts")
    cu.add_argument("--all", action="store_true", help="Clean all artifacts")
    cu.add_argument("--uploads", action="store_true", help="Clean upload directory")
    cu.add_argument("--results", action="store_true", help="Clean results directory")
    cu.add_argument("--analysis", action="store_true", help="Clean analysis artifacts")


_EPILOG = """
Examples:
  # Upload and analyze a file
  %(prog)s upload malware.exe --analysis static dynamic

  # Upload and analyze a kernel driver
  %(prog)s upload-driver rootkit.sys --holygrail

  # Analyze a running process
  %(prog)s analyze-pid 1234 --wait

  # Get comprehensive results
  %(prog)s results abc123def --comprehensive

  # Run Doppelganger operations
  %(prog)s doppelganger-scan --type blender
  %(prog)s doppelganger-analyze abc123def --type fuzzy --threshold 85

  # EDR (Whiskers + Elastic Defend or Fibratus)
  %(prog)s edr-profiles
  %(prog)s edr-status
  %(prog)s edr-run abc123def --profile elastic --wait
  %(prog)s edr-run abc123def --profile fibratus --wait
  %(prog)s edr-results abc123def --profile fibratus

  # EDR testing — verify the Fibratus alert wire without running a payload
  %(prog)s fibratus-alerts --profile fibratus --from 2026-04-30T00:00:00Z

  # System operations
  %(prog)s status --full
  %(prog)s scanners
  %(prog)s cleanup --all

  # Report operations
  %(prog)s report abc123def --browser
  %(prog)s report abc123def --download --output ./reports/
"""
