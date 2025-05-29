# app/analyzers/manager.py

import logging
import subprocess
import time
import psutil
import json
from typing import Dict, Type, Optional, Tuple
from abc import ABC, abstractmethod

# Import analyzers
from .static.yara_analyzer import YaraStaticAnalyzer
from .static.checkplz_analyzer import CheckPlzAnalyzer
from .static.stringnalyzer_analyzer import StringsAnalyzer
from .dynamic.yara_analyzer import YaraDynamicAnalyzer
from .dynamic.pe_sieve_analyzer import PESieveAnalyzer
from .dynamic.moneta_analyzer import MonetaAnalyzer
from .dynamic.patriot_analyzer import PatriotAnalyzer
from .dynamic.hsb_analyzer import HSBAnalyzer
from .dynamic.rededr_analyzer import RedEdrAnalyzer


class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, target):
        pass

    @abstractmethod
    def get_results(self):
        pass


class AnalysisManager:
    # Define analyzer mappings
    STATIC_ANALYZERS = {
        'yara': YaraStaticAnalyzer,
        'checkplz': CheckPlzAnalyzer,
        'stringnalyzer': StringsAnalyzer
    }

    DYNAMIC_ANALYZERS = {
        'yara': YaraDynamicAnalyzer,
        'pe_sieve': PESieveAnalyzer,
        'moneta': MonetaAnalyzer,
        'patriot': PatriotAnalyzer,
        'hsb': HSBAnalyzer,
        'rededr': RedEdrAnalyzer
    }

    def __init__(self, config: dict, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.logger.debug("Initializing AnalysisManager")
        self.config = config
        self.static_analyzers: Dict[str, BaseAnalyzer] = {}
        self.dynamic_analyzers: Dict[str, BaseAnalyzer] = {}
        
        self._initialize_analyzers()

    def _initialize_analyzer(self, name: str, analyzer_class: Type[BaseAnalyzer], config_section: dict) -> Optional[BaseAnalyzer]:
        if not config_section.get('enabled', False):
            self.logger.debug(f"Analyzer {name} is disabled in config")
            return None

        self.logger.debug(f"Initializing {name}")
        try:
            analyzer = analyzer_class(self.config)
            self.logger.debug(f"{name} initialized successfully")
            return analyzer
        except Exception as e:
            self.logger.error(f"Failed to initialize {name}: {e}", exc_info=True)
            return None

    def _initialize_analyzers(self):
        self.logger.debug("Beginning analyzer initialization")
        
        # Initialize static analyzers
        static_config = self.config['analysis']['static']
        for name, analyzer_class in self.STATIC_ANALYZERS.items():
            if analyzer := self._initialize_analyzer(name, analyzer_class, static_config[name]):
                self.static_analyzers[name] = analyzer

        # Initialize dynamic analyzers
        dynamic_config = self.config['analysis']['dynamic']
        for name, analyzer_class in self.DYNAMIC_ANALYZERS.items():
            if analyzer := self._initialize_analyzer(name, analyzer_class, dynamic_config[name]):
                self.dynamic_analyzers[name] = analyzer

        self.logger.debug(f"Initialized static analyzers: {list(self.static_analyzers.keys())}")
        self.logger.debug(f"Initialized dynamic analyzers: {list(self.dynamic_analyzers.keys())}")
        self.logger.debug("Analyzer initialization completed")

    def _run_analyzers(self, analyzers: Dict[str, BaseAnalyzer], target, analysis_type: str) -> dict:
        results = {}
        if not analyzers:
            self.logger.warning(f"No {analysis_type} analyzers are enabled")
            return results

        # For dynamic analysis, verify process exists first
        if analysis_type == 'dynamic':
            if not self._validate_dynamic_target(target):
                return {'status': 'error', 'error': 'Process does not exist or is not running'}

        self.logger.debug(f"Running {len(analyzers)} {analysis_type} analyzers")
        for name, analyzer in analyzers.items():
            try:
                self.logger.debug(f"Running {name}")
                analyzer.analyze(target)
                results[name] = analyzer.get_results()
            except Exception as e:
                self.logger.error(f"Error in {name}: {str(e)}")
                results[name] = {'status': 'error', 'error': str(e)}

        return results

    def _validate_dynamic_target(self, target) -> bool:
        """Validate that the target process exists for dynamic analysis"""
        try:
            process = psutil.Process(int(target))
            return process.is_running()
        except (ValueError, psutil.NoSuchProcess):
            self.logger.error(f"Process {target} does not exist")
            return False

    def _create_metadata(self, start_time: float, **kwargs) -> dict:
        """Create analysis metadata with common fields"""
        metadata = {
            'total_duration': time.time() - start_time,
            'timestamp': time.time()
        }
        metadata.update(kwargs)
        return metadata

    def run_static_analysis(self, file_path: str) -> dict:
        start_time = time.time()
        
        try:
            results = self._run_analyzers(self.static_analyzers, file_path, 'static')
            results['analysis_metadata'] = self._create_metadata(start_time)
            
        except Exception as e:
            self.logger.error(f"Error during static analysis: {str(e)}", exc_info=True)
            results = {'analysis_metadata': self._create_metadata(start_time, error=str(e))}
        
        self.logger.debug(f"Static analysis completed in {time.time() - start_time:.2f} seconds")
        return results

    def run_dynamic_analysis(self, target, is_pid: bool = False, cmd_args: list = None) -> dict:
        self.logger.debug(f"Starting dynamic analysis - Target: {target}, is_pid: {is_pid}, args: {cmd_args}")
        start_time = time.time()
        
        try:
            if is_pid:
                return self._run_pid_analysis(target, start_time)
            else:
                return self._run_file_analysis(target, cmd_args, start_time)
                
        except Exception as e:
            self.logger.error(f"Error during dynamic analysis: {str(e)}", exc_info=True)
            return self._create_error_result(start_time, str(e), cmd_args)

    def _run_pid_analysis(self, target: str, start_time: float) -> dict:
        """Handle PID-based analysis"""
        try:
            process, pid = self._validate_process(target, True)
            results = self._run_analyzers(self.dynamic_analyzers, pid, 'dynamic')
            results['analysis_metadata'] = self._create_metadata(start_time, cmd_args=[])
            return results
        except Exception as e:
            return self._create_error_result(start_time, str(e))

    def _run_file_analysis(self, target: str, cmd_args: list, start_time: float) -> dict:
        """Handle file-based analysis with RedEdr integration"""
        results = {}
        process = None
        rededr = None
        
        try:
            # 1. Start RedEdr if enabled
            rededr = self._initialize_rededr(target, results)
            
            # 2. Validate and start process
            try:
                process, pid = self._validate_process(target, False, cmd_args)
            except Exception as e:
                return self._handle_process_startup_error(e, start_time, cmd_args)
            
            # 3. Run regular analyzers (excluding RedEdr)
            regular_analyzers = {k: v for k, v in self.dynamic_analyzers.items() if k != 'rededr'}
            other_results = self._run_analyzers(regular_analyzers, pid, 'dynamic')
            results.update(other_results)
            
            # 4. Capture process output
            results['process_output'] = self._capture_process_output(process)
            
            # 5. Get RedEdr results and cleanup
            if rededr:
                self.logger.debug("Getting RedEdr events")
                results['rededr'] = rededr.get_results()
                self._cleanup_rededr(rededr)
            
            results['analysis_metadata'] = self._create_metadata(
                start_time, 
                early_termination=False, 
                analysis_started=True, 
                cmd_args=cmd_args or []
            )
            
            return results
            
        except Exception as e:
            return self._create_error_result(start_time, str(e), cmd_args)

    def _initialize_rededr(self, target: str, results: dict):
        """Initialize RedEdr if enabled"""
        rededr_config = self.config['analysis']['dynamic'].get('rededr', {})
        if not rededr_config.get('enabled'):
            return None
            
        self.logger.debug("Initializing RedEdr analyzer")
        try:
            target_name = target.split('\\')[-1]
            rededr = RedEdrAnalyzer(self.config)
            if rededr.start_tool(target_name):
                etw_wait_time = rededr_config.get('etw_wait_time', 5)
                self.logger.debug(f"RedEdr initialized, waiting {etw_wait_time} seconds for ETW setup")
                time.sleep(etw_wait_time)
                return rededr
            else:
                self.logger.error("Failed to start RedEdr")
                results['rededr'] = {'status': 'error', 'error': 'Failed to start tool'}
                return None
        except Exception as e:
            self.logger.error(f"Error initializing RedEdr: {e}")
            results['rededr'] = {'status': 'error', 'error': str(e)}
            return None

    def _cleanup_rededr(self, rededr):
        """Cleanup RedEdr analyzer"""
        self.logger.debug("Cleaning up RedEdr")
        try:
            rededr.cleanup()
        except Exception as e:
            self.logger.error(f"Error cleaning up RedEdr: {e}")

    def _capture_process_output(self, process) -> dict:
        """Capture output from process"""
        if not process:
            return {'had_output': False, 'error': 'No process to capture output from'}
            
        self.logger.debug("Capturing process output")
        try:
            stdout, stderr = process.communicate(timeout=1)
            return {
                'stdout': stdout.strip() if stdout else '',
                'stderr': stderr.strip() if stderr else '',
                'had_output': bool(stdout.strip() or stderr.strip()),
                'output_truncated': False
            }
        except subprocess.TimeoutExpired:
            self.logger.debug("Output capture timed out; killing the process")
            self._cleanup_process(process, False)
            stdout, stderr = process.communicate()
            return {
                'stdout': stdout.strip() if stdout else '',
                'stderr': stderr.strip() if stderr else '',
                'had_output': bool(stdout.strip() or stderr.strip()),
                'output_truncated': False,
                'note': 'Process killed after timeout'
            }
        except Exception as e:
            self.logger.error(f"Error capturing process output: {e}")
            return {'error': str(e), 'had_output': False, 'output_truncated': False}

    def _handle_process_startup_error(self, error: Exception, start_time: float, cmd_args: list) -> dict:
        """Handle errors during process startup"""
        error_msg = str(error)
        self.logger.error(f"Process startup failed: {error_msg}")
        
        if "terminated after" in error_msg:
            init_wait = self.config.get('analysis', {}).get('process', {}).get('init_wait_time', 5)
            return {
                'status': 'early_termination',
                'error': {
                    'message': f'Process terminated before initialization period ({init_wait}s)',
                    'details': error_msg,
                    'termination_time': error_msg.split('terminated after ')[1].split(' seconds')[0],
                    'cmd_args': cmd_args or []
                },
                'analysis_metadata': self._create_metadata(
                    start_time, 
                    early_termination=True, 
                    analysis_started=False, 
                    cmd_args=cmd_args or []
                )
            }
        else:
            return self._create_error_result(start_time, error_msg, cmd_args)

    def _create_error_result(self, start_time: float, error_msg: str, cmd_args: list = None) -> dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': {
                'message': 'Analysis failed',
                'details': error_msg,
                'cmd_args': cmd_args or []
            },
            'analysis_metadata': self._create_metadata(
                start_time, 
                error=error_msg, 
                early_termination=False, 
                analysis_started=False, 
                cmd_args=cmd_args or []
            )
        }

    def _validate_process(self, target, is_pid: bool, cmd_args: list = None) -> Tuple[subprocess.Popen, int]:
        if is_pid:
            return self._validate_existing_pid(target)
        else:
            return self._create_new_process(target, cmd_args)

    def _validate_existing_pid(self, target: str) -> Tuple[psutil.Process, int]:
        """Validate existing PID"""
        self.logger.debug(f"Validating PID: {target}")
        try:
            pid = int(target)
            process = psutil.Process(pid)
            if not process.is_running():
                raise Exception(f"Process with PID {pid} is not running")
            self.logger.debug(f"Successfully validated PID {pid}")
            return process, pid
        except (ValueError, psutil.NoSuchProcess) as e:
            self.logger.error(f"Invalid or non-existent PID {target}: {e}")
            raise Exception(f"Invalid or non-existent PID: {e}")

    def _create_new_process(self, target: str, cmd_args: list) -> Tuple[subprocess.Popen, int]:
        """Create and validate new process"""
        command = [target]
        if cmd_args:
            command.extend(cmd_args)
            
        self.logger.debug(f"Starting new process: {command}")
        
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                startupinfo=startupinfo,
                bufsize=1,
                text=True,
            )
            pid = process.pid
            self.logger.debug(f"Process started with PID: {pid}")

            self._wait_for_process_initialization(process, pid, command)
            return process, pid
            
        except Exception as e:
            raise Exception(f"Failed to start process: {str(e)}")

    def _wait_for_process_initialization(self, process: subprocess.Popen, pid: int, command: list):
        """Wait for process to initialize and validate it's still running"""
        try:
            ps_process = psutil.Process(pid)
            if not ps_process.is_running():
                raise Exception(f"Process {pid} terminated immediately")
            
            init_wait = self.config.get('analysis', {}).get('process', {}).get('init_wait_time', 5)
            self.logger.debug(f"Waiting {init_wait} seconds for process initialization")
            
            wait_interval = 0.1
            elapsed = 0
            while elapsed < init_wait:
                time.sleep(wait_interval)
                elapsed += wait_interval
                
                if not ps_process.is_running():
                    cmd_str = ' '.join(command)
                    raise Exception(f"Process terminated after {elapsed:.1f} seconds (Command: {cmd_str})")
            
            if not ps_process.is_running():
                raise Exception(f"Process terminated during initialization")
                
        except psutil.NoSuchProcess:
            cmd_str = ' '.join(command)
            raise Exception(f"Process {pid} terminated immediately after start (Command: {cmd_str})")
        except Exception as e:
            if process:
                try:
                    process.kill()
                except:
                    pass
            raise e

    def _cleanup_process(self, process, is_pid: bool):
        if process and not is_pid:
            self.logger.debug(f"Starting cleanup of process PID: {process.pid}")
            try:
                try:
                    parent = psutil.Process(process.pid)
                    if not parent.is_running():
                        self.logger.debug(f"Process {process.pid} has already terminated")
                        return
                except psutil.NoSuchProcess:
                    self.logger.debug(f"Process {process.pid} no longer exists")
                    return
                
                # Get and terminate children
                try:
                    children = parent.children(recursive=True)
                    self.logger.debug(f"Found {len(children)} child processes to terminate")
                    
                    for child in children:
                        try:
                            if child.is_running():
                                self.logger.debug(f"Terminating child process: {child.pid}")
                                child.terminate()
                                child.wait(timeout=3)
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                            try:
                                if child.is_running():
                                    child.kill()
                            except psutil.NoSuchProcess:
                                pass
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.logger.error(f"Failed to get child processes: {e}")
                
                # Terminate parent
                try:
                    if parent.is_running():
                        self.logger.debug(f"Terminating parent process: {parent.pid}")
                        parent.terminate()
                        parent.wait(timeout=3)
                        
                        if parent.is_running():
                            self.logger.debug(f"Force killing parent process: {parent.pid}")
                            parent.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
                    self.logger.error(f"Failed to terminate parent process: {e}")
                
                self.logger.debug("Process cleanup completed")
                
            except Exception as e:
                self.logger.error(f"Error during process cleanup: {str(e)}", exc_info=True)