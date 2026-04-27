# app/analyzers/dynamic/hsb_analyzer.py
import re
from datetime import datetime
from ..base import BaseSubprocessAnalyzer


_ANSI_ESCAPE = re.compile(r'(?:\x1B[@-_][0-?]*[ -/]*[@-~])')


class HSBAnalyzer(BaseSubprocessAnalyzer):
    SEVERITY_LEVELS = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MID': 2,
        'LOW': 1,
    }

    tool_section = 'dynamic'
    tool_name = 'hsb'
    target_kwarg = 'pid'

    def _preprocess_stdout(self, stdout):
        return _ANSI_ESCAPE.sub('', stdout)

    def _postprocess_findings(self, findings):
        self._enrich_findings(findings)
        return findings

    def _enrich_findings(self, sections):
        if not sections or 'detections' not in sections:
            return

        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MID': 0, 'LOW': 0}
        total_findings = 0
        max_severity = 0

        for process in sections['detections']:
            for finding in process['findings']:
                severity = finding.get('severity', 'LOW')
                severity_counts[severity] += 1
                total_findings += 1

                severity_score = self.SEVERITY_LEVELS.get(severity, 0)
                if severity_score > max_severity:
                    max_severity = severity_score

            process['total_findings'] = len(process['findings'])
            process['max_severity'] = max_severity

            findings_by_thread = {}
            for finding in process['findings']:
                thread_id = finding.get('thread_id')
                if thread_id:
                    findings_by_thread.setdefault(thread_id, []).append(finding)

            process['findings_by_thread'] = findings_by_thread

        sections['summary'].update({
            'total_findings': total_findings,
            'severity_counts': severity_counts,
            'max_severity': max_severity,
        })

    def _parse_output(self, output):
        sections = {
            'summary': {'duration': 0, 'has_detections': False},
            'detections': [],
        }

        current_process = None

        for line in output.splitlines():
            line = line.rstrip()
            if not line or line.startswith('_') or line.startswith(' _'):
                continue

            if line.startswith('* Detections for:'):
                match = re.search(r'\* Detections for: (.+?)\s*\(\s*(\d+)\s*\)', line)
                if match:
                    current_process = {
                        'process_name': match.group(1).strip(),
                        'pid': int(match.group(2)),
                        'findings': [],
                    }
                    sections['detections'].append(current_process)

            elif line.strip().startswith('!'):
                if current_process:
                    finding = self._parse_finding(
                        line.strip(),
                        current_process['process_name'],
                        current_process['pid'],
                    )
                    if finding:
                        current_process['findings'].append(finding)
                        sections['summary']['has_detections'] = True

            elif line.startswith('* Scanned:'):
                match = re.search(
                    r'Scanned: (\d+) processes and (\d+) threads in (\d+\.?\d*) seconds', line
                )
                if match:
                    sections['summary'].update({
                        'scanned_processes': int(match.group(1)),
                        'scanned_threads': int(match.group(2)),
                        'duration': float(match.group(3)),
                    })

        if not sections['detections']:
            sections['detections'].append({
                'process_name': f"PID {self.pid}",
                'pid': self.pid,
                'findings': [],
            })

        return sections

    def _parse_finding(self, line, process_name, pid):
        line = line[1:].strip()

        finding = {
            'process_name': process_name,
            'pid': pid,
            'type': None,
            'severity': None,
            'description': None,
            'raw_message': line,
            'details': {},
            'timestamp': self._get_timestamp(),
        }

        severity_match = re.search(r'\|\s*Severity:\s*(\w+)$', line)
        if severity_match:
            finding['severity'] = severity_match.group(1)
            line = line.replace(severity_match.group(0), '').rstrip()

        if line.startswith('Suspicious Timer'):
            finding.update(self._parse_suspicious_timer(line))
            return finding

        thread_match = re.search(r'Thread\s+(\d+)\s*\|\s*([^|]+)\s*\|\s*(.+)$', line)
        if not thread_match:
            return None

        thread_id = int(thread_match.group(1))
        finding_type = thread_match.group(2).strip()
        description = thread_match.group(3).strip()

        finding.update({
            'thread_id': thread_id,
            'type': finding_type,
            'description': description,
        })

        parser_method = f'_parse_{finding_type.lower().replace(" ", "_")}'
        if hasattr(self, parser_method):
            finding['details'].update(getattr(self, parser_method)(description))

        return finding

    def _parse_suspicious_timer(self, line):
        details = {'type': 'Suspicious Timer', 'details': {}}

        if 'pointing to' in line:
            target_match = re.search(r'pointing to ([^\s|]+)', line)
            if target_match:
                details['details']['target_function'] = target_match.group(1)

        description = line.split('|')[0].replace('Suspicious Timer', '').strip()
        if '|' in line:
            description = line.split('|')[1].strip().split('|')[0].strip()

        details['description'] = description
        return details

    def _parse_blocking_timer_detected(self, description):
        details = {}
        callback_match = re.search(r'triggered by ([^\s|]+)', description)
        if callback_match:
            details['callback_function'] = callback_match.group(1)
        return details

    def _parse_module_stomping(self, description):
        details = {}
        match = re.search(r'stomped module:\s*(.+)$', description, re.IGNORECASE)
        if match:
            full_module_name = match.group(1).strip()
            details['module_name'] = full_module_name
            if '_' in full_module_name:
                parts = full_module_name.rsplit('_', 1)
                if len(parts) == 2:
                    details['hash_prefix'] = parts[0]
                    details['base_name'] = parts[1]
        return details

    def _parse_abnormal_intermodular_call(self, description):
        details = {}
        pattern = re.compile(r'^(.+?)\s+called\s+(.+?)(?:\.\s+This\s+indicates\s+(.*))?$')
        match = pattern.search(description)
        if match:
            details['caller'] = match.group(1).strip()
            details['callee'] = match.group(2).rstrip('.').strip()
            if match.group(3):
                details['context'] = match.group(3).rstrip('.').strip()
        return details

    def _parse_return_address_spoofing(self, description):
        details = {}
        thread_num_match = re.search(r'Thread\s+(\d+)\s+returns', description)
        if thread_num_match:
            details['target_thread'] = int(thread_num_match.group(1))

        gadget_match = re.search(r'Gadget in:\s+([^\s|]+)', description)
        if gadget_match:
            details.update({
                'gadget_location': gadget_match.group(1),
                'technique': 'JMP gadget',
            })
        return details

    def _get_timestamp(self):
        return datetime.utcnow().isoformat()
