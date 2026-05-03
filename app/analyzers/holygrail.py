# app/analyzers/holygrail.py
import os
import json
import subprocess
import logging
from typing import Optional, Dict, Any
from datetime import datetime

class HolyGrailAnalyzer:
    def __init__(self, config: dict, logger: Optional[logging.Logger] = None):
        self.config = config
        self.logger = logger or logging.getLogger(__name__)

        holygrail_config = config.get('analysis', {}).get('holygrail', {})
        self.enabled = holygrail_config.get('enabled', False)
        self.tool_path = holygrail_config.get('tool_path', '')
        self.policies_path = holygrail_config.get('policies_path', '')
        self.command_template = holygrail_config.get('command', '')
        self.results_path = holygrail_config.get('results_path', '')
        self.timeout = holygrail_config.get('timeout', 120)

    def analyze(self, file_path: str) -> Dict[str, Any]:
        self.logger.debug(f"Starting holygrail analysis of: {file_path}")

        if not self.enabled:
            self.logger.debug("holygrail analyzer is disabled")
            return {'status': 'error', 'error': 'holygrail disabled'}

        if not os.path.exists(self.tool_path):
            self.logger.error(f"holygrail tool not found at: {self.tool_path}")
            return {'status': 'error', 'error': f'Tool not found: {self.tool_path}'}

        if not os.path.exists(file_path):
            self.logger.error(f"File not found: {file_path}")
            return {'status': 'error', 'error': f'File not found: {file_path}'}

        try:
            command = self.command_template.format(
                tool_path=self.tool_path,
                file_path=file_path,
                policies_path=self.policies_path,
                results_path=self.results_path,
            )

            self.logger.debug(f"Executing command: {command}")

            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.logger.debug(f"Command completed with return code: {result.returncode}")

            if result.returncode != 0:
                self.logger.error(f"holygrail tool failed with code {result.returncode}")
                self.logger.error(f"STDERR: {result.stderr}")
                return {
                    'status': 'error',
                    'error': f'Tool failed with code {result.returncode}',
                    'stderr': result.stderr,
                }

            json_data = self._extract_json(result.stdout)

            if json_data:
                self.logger.debug("holygrail analysis completed successfully")
                return {
                    'status': 'completed',
                    'findings': json_data,
                    'timestamp': datetime.now().isoformat(),
                }

            self.logger.error("No JSON found in holygrail output")
            self.logger.debug(f"Raw output: {result.stdout}")
            return {
                'status': 'error',
                'error': 'No JSON found in output',
                'raw_output': result.stdout,
            }

        except subprocess.TimeoutExpired:
            self.logger.error(f"holygrail analysis timed out after {self.timeout} seconds")
            return {'status': 'error', 'error': f'Timeout after {self.timeout} seconds'}
        except Exception as e:
            self.logger.error(f"holygrail analysis failed: {str(e)}")
            return {'status': 'error', 'error': str(e)}

    def _extract_json(self, output: str) -> Optional[Dict[str, Any]]:
        try:
            lines = output.strip().split('\n')

            for i, line in enumerate(lines):
                if line.strip().startswith('{'):
                    json_lines = []
                    brace_count = 0

                    for line in lines[i:]:
                        json_lines.append(line)
                        brace_count += line.count('{') - line.count('}')
                        if brace_count == 0:
                            break

                    return json.loads('\n'.join(json_lines))

        except Exception as e:
            self.logger.error(f"JSON extraction failed: {e}")

        return None
