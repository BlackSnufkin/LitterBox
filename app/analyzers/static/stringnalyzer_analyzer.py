# app/analyzers/static/stringnalyzer_analyzer.py
import json
from ..base import BaseSubprocessAnalyzer


_DEFAULT_FIELDS = {
    'file_path': None,
    'total_strings': 0,
    'all_strings': [],
    'found_error_messages': [],
    'found_functions': [],
    'found_url': [],
    'found_dll': [],
    'found_ip': [],
    'found_path': [],
    'found_file': [],
    'found_commands': [],
    'found_suspicious_strings': [],
    'found_suspicious_functions': [],
    'found_network_indicators': [],
    'found_registry_keys': [],
    'found_interesting_strings': [],
    'found_file_operations': [],
    'found_emails': [],
    'found_domains': [],
}


class StringsAnalyzer(BaseSubprocessAnalyzer):
    tool_section = 'static'
    tool_name = 'stringnalyzer'
    target_kwarg = 'file_path'
    abspath_targets = True
    use_tool_path_as_cwd = True

    def _build_envelope(self, findings, returncode, stderr, stdout, target):
        return {
            'status': 'completed' if returncode == 0 else 'failed',
            'scan_info': {'target': target, 'tool': 'Stringnalyzer'},
            'findings': findings,
            'errors': stderr if stderr else None,
        }

    def _parse_output(self, output):
        try:
            results = json.loads(output)
            for key, default in _DEFAULT_FIELDS.items():
                if key not in results:
                    results[key] = default
            return results
        except json.JSONDecodeError as e:
            return {'error': f'Failed to parse JSON output: {str(e)}', **_DEFAULT_FIELDS}
        except Exception as e:
            return {'error': f'Unexpected error parsing output: {str(e)}', **_DEFAULT_FIELDS}
