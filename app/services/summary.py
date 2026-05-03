# app/services/summary.py
"""Aggregation helpers for the /files endpoint."""
import os

from . import summary_cache
from ..utils import json_helpers, risk_analyzer


def process_pid_summary(item, item_path, pid_based_summary, logger):
    pid = item.replace('dynamic_', '')

    # Cache hit short-circuits the multi-MB JSON parse + risk recompute.
    # The cache validates against source mtimes on read, so a stale
    # entry is impossible — no manual invalidation needed at save sites.
    cached = summary_cache.get_cached(item_path)
    if cached is not None:
        pid_based_summary[pid] = cached
        return

    logger.debug(f"Processing dynamic analysis results for PID: {pid}")

    dynamic_results_path = os.path.join(item_path, 'dynamic_analysis_results.json')
    if not os.path.exists(dynamic_results_path):
        return

    try:
        dynamic_results = json_helpers.load_json_file(dynamic_results_path)
        if not dynamic_results:
            return
        logger.debug(f"Loaded dynamic analysis results for PID: {pid}")

        process_info = dynamic_results.get('moneta', {}).get('findings', {}).get('process_info', {})
        risk_score, risk_factors = risk_analyzer.calculate_risk(
            analysis_type='process', dynamic_results=dynamic_results,
        )
        risk_level = risk_analyzer.get_risk_level(risk_score)

        yara_matches = dynamic_results.get('yara', {}).get('matches', [])
        pe_sieve_findings = dynamic_results.get('pe_sieve', {}).get('findings', {})
        moneta_findings = dynamic_results.get('moneta', {}).get('findings', {})
        hsb_detections = dynamic_results.get('hsb', {}).get('findings', {}).get('detections', [])

        result = {
            'pid': pid,
            'process_name': process_info.get('name', 'unknown'),
            'process_path': process_info.get('path', 'unknown'),
            'architecture': process_info.get('arch', 'unknown'),
            'analysis_time': dynamic_results.get('analysis_time', 'unknown'),
            'result_dir_full_path': os.path.abspath(item_path),
            'risk_assessment': {
                'score': risk_score,
                'level': risk_level,
                'factors': risk_factors,
            },
            'analysis_summary': {
                'yara': {
                    'total_findings': len(yara_matches),
                    'findings': yara_matches,
                },
                'pe_sieve': {
                    'total_findings': pe_sieve_findings.get('total_suspicious', 0),
                    'findings': pe_sieve_findings,
                },
                'moneta': {
                    'total_findings': sum(
                        1 for key, value in moneta_findings.items()
                        if key.startswith('total_') and isinstance(value, (int, float)) and value > 0
                    ),
                    'findings': moneta_findings,
                },
                'hsb': {
                    'total_findings': sum(
                        len(det.get('findings', []))
                        for det in hsb_detections if det.get('pid') == int(pid)
                    ),
                    'findings': [det for det in hsb_detections if det.get('pid') == int(pid)],
                },
            },
        }
        pid_based_summary[pid] = result
        summary_cache.store(item_path, result)
        logger.debug(f"Processed dynamic analysis for PID: {pid}")
    except Exception as e:
        logger.error(f"Error processing PID {pid}: {e}")


def process_file_summary(item, item_path, file_based_summary, logger):
    file_info_path = os.path.join(item_path, 'file_info.json')
    if not os.path.exists(file_info_path):
        logger.debug(f"No file_info.json found in {item_path}. Skipping.")
        return

    # Cache hit short-circuits the per-sample 4-6 disk reads + risk
    # recompute. Validated against source mtimes on read.
    cached = summary_cache.get_cached(item_path)
    if cached is not None:
        file_based_summary[item] = cached
        return

    try:
        file_info = json_helpers.load_json_file(file_info_path)
        if not file_info:
            return
        logger.debug(f"Loaded file info for item: {item}")

        filename = file_info.get('original_name', 'unknown')
        is_driver = filename.lower().endswith('.sys')

        if is_driver:
            byovd_path = os.path.join(item_path, 'byovd_results.json')
            has_static_analysis = os.path.exists(byovd_path)
            has_dynamic_analysis = False

            byovd_results = None
            if has_static_analysis:
                byovd_results = json_helpers.load_json_file(byovd_path)
                logger.debug(f"Loaded BYOVD analysis results for driver: {item}")

            risk_score, risk_factors = risk_analyzer.calculate_risk(
                analysis_type='driver',
                file_info=file_info,
                byovd_results=byovd_results,
            )
        else:
            static_path = os.path.join(item_path, 'static_analysis_results.json')
            dynamic_path = os.path.join(item_path, 'dynamic_analysis_results.json')

            static_results = None
            if os.path.exists(static_path):
                static_results = json_helpers.load_json_file(static_path)
                logger.debug(f"Loaded static analysis results for item: {item}")

            dynamic_results = None
            if os.path.exists(dynamic_path):
                dynamic_results = json_helpers.load_json_file(dynamic_path)
                logger.debug(f"Loaded dynamic analysis results for item: {item}")

            # Discover every EDR profile run for this sample for the
            # Status-cell sub-badges. Stored as `edr_<profile>_results.json`.
            # NOTE: EDR results are NOT folded into the file's risk score.
            # EDR is its own analysis type with its own page; the file's
            # score stays scoped to static+dynamic+PE info.
            edr_results = {}
            edr_prefix, edr_suffix = 'edr_', '_results.json'
            for entry in os.listdir(item_path):
                if entry.startswith(edr_prefix) and entry.endswith(edr_suffix):
                    profile_name = entry[len(edr_prefix):-len(edr_suffix)]
                    loaded = json_helpers.load_json_file(os.path.join(item_path, entry))
                    if loaded:
                        edr_results[profile_name] = loaded

            has_static_analysis = os.path.exists(static_path)
            has_dynamic_analysis = os.path.exists(dynamic_path)
            has_edr_analysis = bool(edr_results)

            risk_score, risk_factors = risk_analyzer.calculate_risk(
                analysis_type='file',
                file_info=file_info,
                static_results=static_results,
                dynamic_results=dynamic_results,
            )

        risk_level = risk_analyzer.get_risk_level(risk_score)

        # Collapse the per-profile EDR runs into a small list the UI can
        # show in the status column without loading the full JSON. Each
        # entry has just the headline: profile, alert count, killed/AV
        # flags, status string.
        edr_runs = []
        if not is_driver:
            for profile_name, edr in (edr_results or {}).items():
                summary = (edr or {}).get('summary') or {}
                exec_block = (edr or {}).get('execution') or {}
                edr_runs.append({
                    'profile': profile_name,
                    'display_name': edr.get('display_name') or profile_name,
                    'status': edr.get('status'),
                    'total_alerts': summary.get('total_alerts') or len(edr.get('alerts') or []),
                    'high_severity_alerts': summary.get('high_severity_alerts'),
                    'blocked_by_av': summary.get('blocked_by_av'),
                    'killed_by_edr': exec_block.get('killed_by_edr'),
                })

        result = {
            'md5': file_info.get('md5', 'unknown'),
            'sha256': file_info.get('sha256', 'unknown'),
            'filename': filename,
            'file_size': file_info.get('size', 0),
            'upload_time': file_info.get('upload_time', 'unknown'),
            'result_dir_full_path': os.path.abspath(item_path),
            'entropy_value': file_info.get('entropy_analysis', {}).get('value', 0),
            'detection_risk': file_info.get('entropy_analysis', {}).get('detection_risk', 'Unknown'),
            'has_static_analysis': has_static_analysis,
            'has_dynamic_analysis': has_dynamic_analysis,
            'has_edr_analysis': has_edr_analysis if not is_driver else False,
            'edr_runs': edr_runs,
            'risk_assessment': {
                'score': risk_score,
                'level': risk_level,
                'factors': risk_factors,
            },
        }
        file_based_summary[item] = result
        # Persist for the next dashboard load — saves the 4-6 disk
        # reads + risk recompute we just paid for.
        summary_cache.store(item_path, result)
        logger.debug(f"Processed file-based analysis for item: {item}")
    except Exception as e:
        logger.error(f"Error processing file item {item}: {e}")
