# app/analyzers/static/checkplz_analyzer.py
from ..base import BaseSubprocessAnalyzer


class CheckPlzAnalyzer(BaseSubprocessAnalyzer):
    tool_section = 'static'
    tool_name = 'checkplz'
    target_kwarg = 'file_path'
    abspath_targets = True
    use_tool_path_as_cwd = True

    def _build_envelope(self, findings, returncode, stderr, stdout, target):
        return {
            'status': 'completed' if returncode == 0 else 'failed',
            'scan_info': {'target': target, 'tool': 'CheckPlz'},
            'findings': findings,
            'errors': stderr if stderr else None,
        }

    def _parse_output(self, output):
        results = {
            'initial_threat': None,
            'scan_results': {
                'file_path': None,
                'file_size': None,
                'scan_duration': None,
                'search_iterations': None,
                'detection_offset': None,
                'relative_location': None,
                'final_threat_detection': None,
                'hex_dump': None,
            },
        }

        if not output:
            return results

        current_section = None
        hex_dump_lines = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("File Path:"):
                results['scan_results']['file_path'] = line.split(":", 1)[1].strip()
                continue

            if line.startswith("File Size:"):
                results['scan_results']['file_size'] = line.split(":", 1)[1].strip()
                continue

            if "Threat found in the original file:" in line:
                results['initial_threat'] = line.split(":", 1)[1].strip()
                continue

            if "Windows Defender Scan Results" in line:
                current_section = "results"
                continue

            if "Hex Dump Analysis" in line:
                current_section = "hex_dump"
                continue

            if all(c in "=-" for c in line):
                continue

            if current_section == "results" and ":" in line:
                key, value = [x.strip() for x in line.split(":", 1)]

                if "Scan Duration" in key:
                    try:
                        results['scan_results']['scan_duration'] = float(value.replace('s', ''))
                    except (ValueError, TypeError):
                        results['scan_results']['scan_duration'] = value
                elif "Search Iterations" in key:
                    try:
                        results['scan_results']['search_iterations'] = int(value)
                    except (ValueError, TypeError):
                        results['scan_results']['search_iterations'] = value
                elif "Detection Offset" in key:
                    results['scan_results']['detection_offset'] = value
                elif "Relative Location" in key:
                    results['scan_results']['relative_location'] = value
                elif "Final threat detection" in key:
                    results['scan_results']['final_threat_detection'] = value

            elif current_section == "hex_dump" and not line.startswith("Showing"):
                hex_dump_lines.append(line)

        if hex_dump_lines:
            results['scan_results']['hex_dump'] = '\n'.join(hex_dump_lines)

        return results
