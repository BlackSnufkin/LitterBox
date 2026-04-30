"""Command handlers — one `_cmd_*` per CLI subcommand, plus the
`COMMAND_HANDLERS` dispatch table. Each handler is intentionally thin:
it pulls fields off `args`, calls the right client method(s), and
prints / json.dumps the result.

Grouped by domain via comment headers to mirror the parser layout.
"""

import json
import sys
from typing import Dict

from litterbox_client import LitterBoxClient


# =============================================================================
# Intake — upload, analyze-pid, delete
# =============================================================================


def _cmd_upload(client: LitterBoxClient, args):
    result = client.upload_file(args.file, file_name=args.name)
    file_hash = result["file_info"]["md5"]
    print(f"File uploaded successfully. Hash: {file_hash}")

    for analysis_type in args.analysis or []:
        print(f"Running {analysis_type} analysis...")
        analysis_args = args.args if analysis_type == "dynamic" else None
        result = client.analyze_file(
            file_hash, analysis_type,
            cmd_args=analysis_args, wait_for_completion=True,
        )
        _print_analysis_result(result)


def _cmd_upload_driver(client: LitterBoxClient, args):
    result = client.upload_and_analyze_driver(
        args.file, file_name=args.name, run_holygrail=args.holygrail,
    )
    file_hash = result["upload"]["file_info"]["md5"]
    print(f"Driver uploaded successfully. Hash: {file_hash}")

    if args.holygrail and result["holygrail"]:
        if "error" in result["holygrail"]:
            print(f"HolyGrail analysis failed: {result['holygrail']['error']}")
        else:
            print("HolyGrail analysis completed")
            print(json.dumps(result["holygrail"], indent=2))


def _cmd_analyze_pid(client: LitterBoxClient, args):
    print(f"Analyzing process {args.pid}...")
    result = client.analyze_file(
        str(args.pid), "dynamic",
        cmd_args=args.args, wait_for_completion=args.wait,
    )
    _print_analysis_result(result)


def _cmd_delete(client: LitterBoxClient, args):
    print("Deletion Results:")
    print(json.dumps(client.delete_file(args.hash), indent=2))


# =============================================================================
# Results
# =============================================================================


def _cmd_results(client: LitterBoxClient, args):
    if args.comprehensive:
        result = client.get_comprehensive_results(args.target)
        print("Comprehensive Results:")
        print(json.dumps(result, indent=2))
        return

    if not args.type:
        print("Please specify --type or use --comprehensive")
        sys.exit(1)

    if args.type == "holygrail":
        result = client.get_holygrail_results(args.target)
    else:
        result = client.get_results(args.target, args.type)
    print(json.dumps(result, indent=2))


# =============================================================================
# EDR — Whiskers + Elastic / Fibratus
# =============================================================================


def _cmd_edr_run(client: LitterBoxClient, args):
    print(f"Dispatching {args.hash} to EDR profile '{args.profile}'...")
    phase1 = client.analyze_edr(
        args.hash, args.profile,
        cmd_args=args.args, xor_key=args.xor_key,
    )
    print("Phase-1 result:")
    print(json.dumps(phase1, indent=2))

    if args.wait and (phase1 or {}).get("status") == "polling_alerts":
        print(f"\nPolling for Phase-2 settle (timeout {args.timeout}s)...")
        final = client.wait_for_edr_completion(args.hash, args.profile, timeout=args.timeout)
        print("Phase-2 result:")
        print(json.dumps(final, indent=2))


def _cmd_edr_results(client: LitterBoxClient, args):
    if args.profile:
        result = client.get_edr_results(args.hash, args.profile)
    else:
        result = client.get_edr_index(args.hash)
    print(json.dumps(result, indent=2))


def _cmd_edr_profiles(client: LitterBoxClient, args):
    print(json.dumps(client.list_edr_profiles(), indent=2))


def _cmd_edr_status(client: LitterBoxClient, args):
    print(json.dumps(client.get_edr_agents_status(), indent=2))


def _cmd_scanners(client: LitterBoxClient, args):
    print(json.dumps(client.get_scanners_status(), indent=2))


def _cmd_fibratus_alerts(client: LitterBoxClient, args):
    result = client.fibratus_alerts_since(args.profile, args.since, args.until)
    if not result.get("supported", True):
        print(f"Profile '{args.profile}' agent reports Fibratus is NOT installed (telemetry_sources empty).")
        print("Confirm C:\\Program Files\\Fibratus\\Bin\\fibratus.exe exists on the VM.")
        return
    events = result.get("events") or []
    print(f"Fibratus alerts for profile '{args.profile}' between {args.since} and {args.until or 'now'}:")
    print(f"  count: {len(events)}")
    if events:
        # First 5 alert titles + severities for a quick sanity read.
        # Full JSON for everything follows so tools can pipe it.
        for ev in events[:5]:
            try:
                payload = json.loads(ev.get("data") or "{}")
            except (ValueError, TypeError):
                payload = {}
            t = payload.get("title") or "<unparsed>"
            sev = payload.get("severity") or "?"
            ts = ev.get("time_created") or "?"
            print(f"  - [{sev:>8}] {ts}  {t}")
        if len(events) > 5:
            print(f"  ... and {len(events) - 5} more")
    print()
    print(json.dumps(result, indent=2))


# =============================================================================
# Doppelganger
# =============================================================================


def _cmd_doppelganger_scan(client: LitterBoxClient, args):
    print(f"Running doppelganger scan with type: {args.type}")
    print(json.dumps(client.run_blender_scan(), indent=2))


def _cmd_doppelganger_analyze(client: LitterBoxClient, args):
    print(f"Running doppelganger analysis with type: {args.type}")
    if args.type == "blender":
        result = client.compare_with_blender(args.hash)
    else:
        result = client.analyze_with_fuzzy(args.hash, args.threshold)
    print(json.dumps(result, indent=2))


def _cmd_doppelganger_db(client: LitterBoxClient, args):
    print("Creating doppelganger fuzzy database...")
    print(json.dumps(client.create_fuzzy_database(args.folder, args.extensions), indent=2))


# =============================================================================
# Reports
# =============================================================================


def _cmd_report(client: LitterBoxClient, args):
    if args.browser:
        print(f"Opening report for {args.target} in browser...")
        if not client.open_report_in_browser(args.target):
            print("Failed to open report in browser.")
            sys.exit(1)
    elif args.download:
        print(f"Downloading report for {args.target}...")
        output_path = client.download_report(args.target, args.output)
        print(f"Report saved to: {output_path}")
    else:
        print(client.get_report(args.target))


# =============================================================================
# System
# =============================================================================


def _cmd_status(client: LitterBoxClient, args):
    if args.full:
        result = client.get_system_status()
        print("System Status:")
    else:
        result = client.check_health()
        print("Health Check:")
    print(json.dumps(result, indent=2))


def _cmd_health(client: LitterBoxClient, args):
    result = client.check_health()
    status = result.get("status", "unknown")
    print("Service is healthy" if status == "ok" else f"Service status: {status}")
    print(json.dumps(result, indent=2))


def _cmd_files(client: LitterBoxClient, args):
    print("Files Summary:")
    print(json.dumps(client.get_files_summary(), indent=2))


def _cmd_cleanup(client: LitterBoxClient, args):
    if args.all:
        args.uploads = args.results = args.analysis = True
    result = client.cleanup(
        include_uploads=args.uploads,
        include_results=args.results,
        include_analysis=args.analysis,
    )
    print("Cleanup Results:")
    print(json.dumps(result, indent=2))


# =============================================================================
# Shared formatting helper
# =============================================================================


def _print_analysis_result(result: Dict):
    """Pretty-print an `analyze_file` result, branching on status."""
    status = result.get("status", "unknown")

    if status == "early_termination":
        print("Process terminated early:")
        print(f"   Error: {result.get('error')}")
        details = result.get("details", {})
        if details:
            print("   Details:")
            for key, value in details.items():
                print(f"     {key}: {value}")
    elif status == "error":
        print(f"Analysis failed: {result.get('error')}")
        if "details" in result:
            print(f"   Details: {result['details']}")
    elif status == "success":
        print("Analysis completed successfully")
        print(json.dumps(result.get("results", result), indent=2))
    else:
        print(json.dumps(result, indent=2))


# =============================================================================
# Dispatch table — keyed by the CLI subcommand name. The orchestrator
# (grumpycat.py) looks up the right handler here.
# =============================================================================


COMMAND_HANDLERS = {
    "upload":                _cmd_upload,
    "upload-driver":         _cmd_upload_driver,
    "analyze-pid":           _cmd_analyze_pid,
    "delete":                _cmd_delete,
    "results":               _cmd_results,
    "edr-run":               _cmd_edr_run,
    "edr-results":           _cmd_edr_results,
    "edr-profiles":          _cmd_edr_profiles,
    "edr-status":            _cmd_edr_status,
    "fibratus-alerts":       _cmd_fibratus_alerts,
    "scanners":              _cmd_scanners,
    "doppelganger-scan":     _cmd_doppelganger_scan,
    "doppelganger-analyze":  _cmd_doppelganger_analyze,
    "doppelganger-db":       _cmd_doppelganger_db,
    "report":                _cmd_report,
    "status":                _cmd_status,
    "health":                _cmd_health,
    "files":                 _cmd_files,
    "cleanup":               _cmd_cleanup,
}
