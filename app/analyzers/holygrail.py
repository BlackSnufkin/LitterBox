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
        # rename to results_path and use consistently
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
            # Build command
            command = self.command_template.format(
                tool_path=self.tool_path,
                file_path=file_path,
                policies_path=self.policies_path,
                results_path=self.results_path,   # <— ensure provided
            )
            
            self.logger.debug(f"Executing command: {command}")
            
            # Run command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            self.logger.debug(f"Command completed with return code: {result.returncode}")
            
            if result.returncode != 0:
                self.logger.error(f"holygrail tool failed with code {result.returncode}")
                self.logger.error(f"STDERR: {result.stderr}")
                return {
                    'status': 'error',
                    'error': f'Tool failed with code {result.returncode}',
                    'stderr': result.stderr
                }
            
            # Find JSON in output
            json_data = self._extract_json(result.stdout)
            
            if json_data:
                self.logger.debug("holygrail analysis completed successfully")
                return {
                    'status': 'completed',
                    'findings': json_data,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                self.logger.error("No JSON found in holygrail output")
                self.logger.debug(f"Raw output: {result.stdout}")
                return {
                    'status': 'error',
                    'error': 'No JSON found in output',
                    'raw_output': result.stdout
                }
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"holygrail analysis timed out after {self.timeout} seconds")
            return {'status': 'error', 'error': f'Timeout after {self.timeout} seconds'}
        except Exception as e:
            self.logger.error(f"holygrail analysis failed: {str(e)}")
            return {'status': 'error', 'error': str(e)}
        
        # --- below remains as-is; add results_path to its .format too ---
        add_debug(f"Starting analysis - file_path: {file_path}")
        add_debug(f"Config - enabled: {self.enabled}")
        add_debug(f"Config - tool_path: {self.tool_path}")
        add_debug(f"Config - policies_path: {self.policies_path}")
        add_debug(f"Config - timeout: {self.timeout}")
        
        if not self.enabled:
            add_debug("FAILED: holygrail is disabled in config")
            result = {'status': 'error', 'error': 'holygrail disabled'}
            if debug_mode:
                result['debug_output'] = debug_info
            return result
        
        add_debug(f"Checking tool exists: {self.tool_path}")
        if not os.path.exists(self.tool_path):
            add_debug(f"FAILED: Tool not found at {self.tool_path}")
            result = {'status': 'error', 'error': f'Tool not found: {self.tool_path}'}
            if debug_mode:
                result['debug_output'] = debug_info
            return result
        add_debug("Tool exists - OK")
        
        add_debug(f"Checking policies exist: {self.policies_path}")
        if not os.path.exists(self.policies_path):
            add_debug(f"WARNING: Policies path not found: {self.policies_path}")
        else:
            add_debug("Policies path exists - OK")
        
        add_debug(f"Checking file exists: {file_path}")
        if not os.path.exists(file_path):
            add_debug(f"FAILED: File not found at {file_path}")
            result = {'status': 'error', 'error': f'File not found: {file_path}'}
            if debug_mode:
                result['debug_output'] = debug_info
            return result
        add_debug("Target file exists - OK")
        
        try:
            # Build command (debug path)
            command = self.command_template.format(
                tool_path=self.tool_path,
                file_path=file_path,
                policies_path=self.policies_path,
                results_path=self.results_path,   # <— ensure provided here too
            )
            
            add_debug(f"Built command: {command}")
            add_debug(f"Running with timeout: {self.timeout} seconds")
            
            # Run command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            add_debug(f"Command completed - return code: {result.returncode}")
            add_debug(f"STDOUT length: {len(result.stdout)} chars")
            add_debug(f"STDERR length: {len(result.stderr)} chars")
            
            if debug_mode:
                add_debug(f"STDOUT content: {result.stdout}")
                add_debug(f"STDERR content: {result.stderr}")
            
            if result.returncode != 0:
                add_debug(f"FAILED: Tool returned error code {result.returncode}")
                error_result = {
                    'status': 'error',
                    'error': f'Tool failed with code {result.returncode}',
                    'stderr': result.stderr
                }
                if debug_mode:
                    error_result['debug_output'] = debug_info
                return error_result
            
            add_debug("Tool executed successfully")
            
            # Find JSON in output
            add_debug("Searching for JSON in output...")
            json_data = self._extract_json(result.stdout, debug_info if debug_mode else None)
            
            if json_data:
                add_debug("JSON extracted successfully")
                add_debug(f"JSON keys found: {list(json_data.keys())}")
                success_result = {
                    'status': 'completed',
                    'findings': json_data,
                    'timestamp': datetime.now().isoformat()
                }
                if debug_mode:
                    success_result['debug_output'] = debug_info
                return success_result
            else:
                add_debug("FAILED: No JSON found in output")
                error_result = {
                    'status': 'error',
                    'error': 'No JSON found in output',
                    'raw_output': result.stdout
                }
                if debug_mode:
                    error_result['debug_output'] = debug_info
                return error_result
                
        except subprocess.TimeoutExpired:
            add_debug(f"FAILED: Command timed out after {self.timeout} seconds")
            error_result = {'status': 'error', 'error': f'Timeout after {self.timeout} seconds'}
            if debug_mode:
                error_result['debug_output'] = debug_info
            return error_result
        except Exception as e:
            add_debug(f"FAILED: Exception occurred: {str(e)}")
            error_result = {'status': 'error', 'error': str(e)}
            if debug_mode:
                error_result['debug_output'] = debug_info
            return error_result.logger.info(f"Running: {command}")
            
            # (unchanged code below)

            
            # Run command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                return {
                    'status': 'error',
                    'error': f'Tool failed: {result.stderr}',
                    'stdout': result.stdout
                }
            
            # Find JSON in output
            json_data = self._extract_json(result.stdout)
            
            if json_data:
                return {
                    'status': 'completed',
                    'findings': json_data,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {
                    'status': 'error',
                    'error': 'No JSON found in output',
                    'stdout': result.stdout
                }
                
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _extract_json(self, output: str) -> Optional[Dict[str, Any]]:
        try:
            lines = output.strip().split('\n')
            
            for i, line in enumerate(lines):
                if line.strip().startswith('{'):
                    # Get JSON block
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