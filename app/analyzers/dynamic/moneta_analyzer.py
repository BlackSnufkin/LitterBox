# app/analyzers/dynamic/moneta_analyzer.py
import re
from ..base import BaseSubprocessAnalyzer


class MonetaAnalyzer(BaseSubprocessAnalyzer):
    tool_section = 'dynamic'
    tool_name = 'moneta'
    target_kwarg = 'pid'
    use_timeout = False  # Moneta historically runs without an explicit timeout

    def _build_envelope(self, findings, returncode, stderr, stdout, target):
        has_results = bool(stdout and findings.get('raw_output'))
        return {
            'status': 'completed' if has_results else 'failed',
            'findings': findings,
            'errors': stderr if stderr else None,
        }

    def _parse_output(self, output):
        findings = {
            'process_info': None,
            'memory_regions': [],
            'total_regions': 0,
            'total_private_rx': 0,
            'total_private_rwx': 0,
            'total_abnormal_private_exec': 0,
            'total_heap_executable': 0,
            'total_modified_code': 0,
            'total_modified_pe_header': 0,
            'total_inconsistent_x': 0,
            'total_unsigned_modules': 0,
            'total_missing_peb': 0,
            'total_mismatching_peb': 0,
            'total_threads_non_image': 0,
            'threads': [],
            'scan_duration': None,
            'raw_output': output,
        }

        try:
            for line in output.split('\n'):
                line = line.rstrip()
                if not line or 'Moneta v1.0' in line or '_____' in line:
                    continue

                if 'scan completed' in line:
                    duration_match = re.search(r'(\d+\.\d+) second', line)
                    if duration_match:
                        findings['scan_duration'] = float(duration_match.group(1))
                    continue

                if '.exe :' in line:
                    process_match = re.match(
                        r'(.+\.exe)\s*:\s*(\d+)\s*:\s*(x64|Wow64)\s*:\s*(.+)', line
                    )
                    if process_match:
                        findings['process_info'] = {
                            'name': process_match.group(1),
                            'pid': process_match.group(2),
                            'arch': process_match.group(3),
                            'path': process_match.group(4),
                        }
                    continue

                if '|' not in line and 'Thread' not in line and '[TID' not in line:
                    continue

                leading_spaces = len(line) - len(line.lstrip())

                if leading_spaces >= 6 and '[TID' in line:
                    tid_match = re.search(r'\[TID\s*(0x[0-9A-Fa-f]+)\]', line)
                    if tid_match:
                        tid = tid_match.group(1)
                        if tid not in [t['tid'] for t in findings['threads']]:
                            findings['threads'].append({
                                'tid': tid,
                                'thread_obj': line.split('Thread')[1].split('[TID')[0].strip()
                                              if 'Thread' in line else None,
                            })
                    continue

                parts = [p.strip() for p in line.split('|')]

                if leading_spaces == 2:
                    findings['total_regions'] += 1
                    full_line = '|'.join(parts[2:])

                    if 'Unsigned module' in full_line:
                        findings['total_unsigned_modules'] += 1
                    if 'Missing PEB module' in full_line:
                        findings['total_missing_peb'] += 1
                    if 'Mismatching PEB module' in full_line:
                        findings['total_mismatching_peb'] += 1

                elif leading_spaces == 4 and len(parts) >= 2:
                    perms = parts[1].strip()
                    flags = ' '.join(parts[2:])

                    if 'Thread within non-image memory region' in flags:
                        findings['total_threads_non_image'] += 1

                    if 'Abnormal private executable memory' in flags:
                        findings['total_abnormal_private_exec'] += 1
                        if 'RWX' in perms:
                            findings['total_private_rwx'] += 1
                        elif 'RX' in perms:
                            findings['total_private_rx'] += 1

                    if 'Heap' in flags and ('RWX' in perms or 'RX' in perms):
                        findings['total_heap_executable'] += 1

                    if 'Modified code' in flags:
                        findings['total_modified_code'] += 1

                    if 'Modified PE header' in flags:
                        findings['total_modified_pe_header'] += 1

                    if 'Inconsistent +x between disk and memory' in flags:
                        findings['total_inconsistent_x'] += 1

        except Exception as e:
            findings['parse_error'] = str(e)

        return findings
