# app/analyzers/dynamic/hollows_hunter_analyzer.py
import json
import logging
from ..base import BaseSubprocessAnalyzer


class HollowsHunterAnalyzer(BaseSubprocessAnalyzer):
    tool_section = 'dynamic'
    tool_name = 'hollows_hunter'
    target_kwarg = 'directory'
    use_timeout = False

    def __init__(self, config):
        super().__init__(config)
        self.logger = logging.getLogger("LitterBox")

    def _parse_output(self, stdout):
        json_start = stdout.find('{')
        if json_start == -1:
            return None
        return json.loads(stdout[json_start:])

    def _build_envelope(self, findings, returncode, stderr, stdout, target):
        if stderr:
            self.logger.warning(f"HollowsHunter stderr: {stderr}")
        if findings is None:
            return {'status': 'failed', 'error': 'No JSON found in output'}
        return {**findings, 'status': 'completed'}

    def _on_error(self, exc):
        self.logger.error(f"Error in HollowsHunter analysis: {str(exc)}")
        return {'status': 'error', 'error': str(exc)}
