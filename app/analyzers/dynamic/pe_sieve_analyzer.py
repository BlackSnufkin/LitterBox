# app/analyzers/dynamic/pe_sieve_analyzer.py
from ..base import BaseSubprocessAnalyzer


class PESieveAnalyzer(BaseSubprocessAnalyzer):
    tool_section = 'dynamic'
    tool_name = 'pe_sieve'
    target_kwarg = 'pid'

    def _build_envelope(self, findings, returncode, stderr, stdout, target):
        # pe-sieve's own returncode is unreliable; presence of parsed output is the
        # success signal.
        has_results = bool(stdout and findings.get('raw_output'))
        return {
            'status': 'completed' if has_results else 'failed',
            'findings': findings,
            'errors': stderr if stderr else None,
        }

    def _parse_output(self, output):
        findings = {
            'total_scanned': 0,
            'skipped': 0,
            'hooked': 0,
            'replaced': 0,
            'hdrs_modified': 0,
            'iat_hooks': 0,
            'implanted': 0,
            'implanted_pe': 0,
            'implanted_shc': 0,
            'unreachable': 0,
            'other': 0,
            'total_suspicious': 0,
            'raw_output': output,
        }

        try:
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                if "Total scanned:" in line:
                    findings['total_scanned'] = int(line.split(':')[1].strip())
                elif "Skipped:" in line:
                    findings['skipped'] = int(line.split(':')[1].strip())
                elif "Hooked:" in line:
                    findings['hooked'] = int(line.split(':')[1].strip())
                elif "Replaced:" in line:
                    findings['replaced'] = int(line.split(':')[1].strip())
                elif "Hdrs Modified:" in line:
                    findings['hdrs_modified'] = int(line.split(':')[1].strip())
                elif "IAT Hooks:" in line:
                    findings['iat_hooks'] = int(line.split(':')[1].strip())
                elif "Implanted:" in line:
                    findings['implanted'] = int(line.split(':')[1].strip())
                elif "Implanted PE:" in line:
                    findings['implanted_pe'] = int(line.split(':')[1].strip())
                elif "Implanted shc:" in line:
                    findings['implanted_shc'] = int(line.split(':')[1].strip())
                elif "Unreachable files:" in line:
                    findings['unreachable'] = int(line.split(':')[1].strip())
                elif "Other:" in line:
                    findings['other'] = int(line.split(':')[1].strip())
                elif "Total suspicious:" in line:
                    findings['total_suspicious'] = int(line.split(':')[1].strip())
        except Exception:
            pass

        return findings
