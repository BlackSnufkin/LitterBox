# app/utils/json_helpers.py
"""JSON I/O, formatting, and detection-count extraction helpers."""
import json
import os


def load_json_file(filepath):
    """Safely load a JSON file. Returns None if missing or unreadable."""
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON file {filepath}: {str(e)}")
        return None


def format_hex(value):
    """Format a value as a lowercase hexadecimal string."""
    if isinstance(value, str) and value.startswith('0x'):
        return value.lower()
    try:
        return f"0x{int(value):x}"
    except (ValueError, TypeError):
        return str(value)


def format_size(size_bytes):
    """Format a byte count as a human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def extract_detection_counts(results):
    """Extract per-analyzer detection counts from a results dict."""
    counts = {'yara': 0, 'pesieve': 0, 'moneta': 0, 'patriot': 0, 'hsb': 0}

    try:
        yara_matches = results.get('yara', {}).get('matches', [])
        counts['yara'] = (
            len({match.get('rule') for match in yara_matches if match.get('rule')})
            if isinstance(yara_matches, list) else 0
        )

        pesieve_findings = results.get('pe_sieve', {}).get('findings', {})
        counts['pesieve'] = int(pesieve_findings.get('total_suspicious', 0) or 0)

        moneta_findings = results.get('moneta', {}).get('findings', {})
        non_detection_fields = ['total_regions', 'total_unsigned_modules', 'scan_duration']
        counts['moneta'] = sum(
            int(moneta_findings.get(key, 0) or 0)
            for key in moneta_findings
            if key.startswith('total_') and key not in non_detection_fields
        )

        patriot_findings = results.get('patriot', {}).get('findings', {}).get('findings', [])
        counts['patriot'] = len(patriot_findings) if isinstance(patriot_findings, list) else 0

        hsb_findings = results.get('hsb', {}).get('findings', {})
        if hsb_findings and hsb_findings.get('detections'):
            counts['hsb'] = len(hsb_findings['detections'][0].get('findings', []))

    except (TypeError, ValueError, IndexError):
        pass

    return counts
