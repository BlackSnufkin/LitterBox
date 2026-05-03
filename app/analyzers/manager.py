# app/analyzers/manager.py

import logging
import subprocess
import time
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
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

    # Analyzers that must run serially AFTER the parallel batch finishes.
    # HSB (Hunt-Sleeping-Beacons) measures the target's sleep / thread
    # timing — concurrent inspection by PE-Sieve / Moneta / Patriot
    # opens handles, walks VAD, and can briefly suspend threads, which
    # would distort the timing pattern HSB observes. Run it solo at the
    # end so its measurements are clean.
    _SERIAL_DYNAMIC_ANALYZERS = frozenset({'hsb'})

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
        """Run a group of analyzers and return their findings keyed by name.

        Static analyzers all run in parallel — they're independent
        subprocesses operating on the same on-disk file with their own
        output dirs / stdout. Wall time drops from sum(tools) to
        max(tools).

        Dynamic analyzers split into two groups: parallel-safe (yara,
        pe_sieve, moneta, patriot — read-only IOC scanners) and serial
        (anything in `_SERIAL_DYNAMIC_ANALYZERS`, currently just hsb,
        whose sleep-timing measurements are perturbed by concurrent
        process inspection from the others). The serial group runs AFTER
        the parallel batch completes so HSB sees a quiescent target.

        Each analyzer is wrapped so a single failure can't bring down
        the rest of the group — the failed entry gets a
        `{status: 'error', error: ...}` envelope and the others keep
        running.
        """
        results = {}
        if not analyzers:
            self.logger.warning(f"No {analysis_type} analyzers are enabled")
            return results

        # For dynamic analysis, verify process exists first
        if analysis_type == 'dynamic':
            if not self._validate_dynamic_target(target):
                return {'status': 'error', 'error': 'Process does not exist or is not running'}

        # Partition into parallel + serial groups. Static is fully
        # parallel; dynamic respects the _SERIAL_DYNAMIC_ANALYZERS set.
        if analysis_type == 'dynamic':
            parallel = {n: a for n, a in analyzers.items() if n not in self._SERIAL_DYNAMIC_ANALYZERS}
            serial   = {n: a for n, a in analyzers.items() if n in self._SERIAL_DYNAMIC_ANALYZERS}
        else:
            parallel = dict(analyzers)
            serial   = {}

        self.logger.debug(
            f"Running {analysis_type} analyzers — parallel: {list(parallel)}, "
            f"serial: {list(serial)}"
        )

        if parallel:
            results.update(self._run_in_parallel(parallel, target))
        for name, analyzer in serial.items():
            results[name] = self._run_one(name, analyzer, target)

        return results

    def _run_one(self, name: str, analyzer: BaseAnalyzer, target) -> dict:
        """Run one analyzer, catching exceptions so a single failure
        doesn't take down the rest of the batch. Logs start + completion
        with per-tool wall time so the operator can see progress in the
        debug log."""
        self.logger.debug(f"Running {name}")
        t0 = time.monotonic()
        try:
            analyzer.analyze(target)
            result = analyzer.get_results()
        except Exception as e:
            self.logger.error(f"Error in {name}: {str(e)}")
            result = {'status': 'error', 'error': str(e)}
        elapsed = time.monotonic() - t0
        self.logger.debug(f"{name} finished in {elapsed:.2f}s")
        return result

    def _run_in_parallel(self, analyzers: Dict[str, BaseAnalyzer], target) -> dict:
        """Drive `analyzers` concurrently via a thread pool sized to the
        batch. All analyzers shell out to subprocesses, so the GIL doesn't
        bottleneck wall time — this gets us roughly max(per-tool wall
        time) instead of sum(per-tool wall time)."""
        results: Dict[str, dict] = {}
        max_workers = min(len(analyzers), 8) or 1
        t0 = time.monotonic()
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='analyzer') as pool:
            futures = {pool.submit(self._run_one, name, a, target): name
                       for name, a in analyzers.items()}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    results[name] = fut.result()
                except Exception as e:
                    # _run_one already swallows exceptions; this is the
                    # belt-and-braces path for anything that escapes it.
                    self.logger.error(f"Error in {name}: {str(e)}")
                    results[name] = {'status': 'error', 'error': str(e)}
        self.logger.debug(
            f"Parallel batch finished in {time.monotonic() - t0:.2f}s: {list(results)}"
        )
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
        """Handle file-based analysis with RedEdr integration.

        RedEdr cleanup is in `finally` so an orphaned RedEdr can never outlive
        a crashed/early-terminated payload. Whatever telemetry RedEdr managed
        to collect is also attached to the response on failure paths, so the
        user sees partial events instead of nothing.
        """
        results = {}
        process = None
        rededr = None
        response = None

        try:
            # 1. Start RedEdr if enabled
            rededr = self._initialize_rededr(target, results)

            # 2. Validate and start process
            try:
                process, pid = self._validate_process(target, False, cmd_args)
            except Exception as e:
                response = self._handle_process_startup_error(e, start_time, cmd_args)
                return response

            # 3. Run regular analyzers (excluding RedEdr)
            regular_analyzers = {k: v for k, v in self.dynamic_analyzers.items() if k != 'rededr'}
            other_results = self._run_analyzers(regular_analyzers, pid, 'dynamic')
            results.update(other_results)

            # 4. Capture process output
            results['process_output'] = self._capture_process_output(process)

            # 5. Get RedEdr results — cleanup is unconditional, in finally.
            if rededr:
                self.logger.debug("Getting RedEdr events")
                results['rededr'] = rededr.get_results()

            results['analysis_metadata'] = self._create_metadata(
                start_time,
                early_termination=False,
                analysis_started=True,
                cmd_args=cmd_args or []
            )
            response = results
            return response

        except Exception as e:
            response = self._create_error_result(start_time, str(e), cmd_args)
            return response

        finally:
            # Always tear down RedEdr — even on early return / exception —
            # so a crashed payload never leaves an orphaned RedEdr process.
            # Cleanup is idempotent, so calling it after the happy-path
            # get_results() is safe.
            if rededr is not None:
                # Attach partial RedEdr telemetry to the response on failure
                # paths (early termination, generic exception). The happy
                # path already populated results['rededr'] in step 5.
                if isinstance(response, dict) and 'rededr' not in response:
                    try:
                        response['rededr'] = rededr.get_results()
                    except Exception as e:
                        self.logger.error(f"Failed to capture partial RedEdr telemetry: {e}")
                try:
                    self._cleanup_rededr(rededr)
                except Exception as e:
                    self.logger.error(f"Error during RedEdr cleanup: {e}")

    def _initialize_rededr(self, target: str, results: dict):
        """Initialize RedEdr if enabled.

        Blocks until RedEdr logs that all ETW providers are attached
        (typically 1-3s). No timeout — failure surfaces as a quick subprocess
        exit, which the reader thread also unblocks on. Callers that want a
        hard deadline get it from the surrounding analysis-pipeline timeout.
        """
        rededr_config = self.config['analysis']['dynamic'].get('rededr', {})
        if not rededr_config.get('enabled'):
            return None

        self.logger.debug("Initializing RedEdr analyzer")
        try:
            # For DLL targets we spawn `rundll32.exe <dll>,<entry>` — the
            # actual running process is rundll32, not the DLL. RedEdr's
            # --trace filter takes a process name, so point it at
            # rundll32.exe to capture ETW from the DLL's host process.
            if target.lower().endswith('.dll'):
                target_name = 'rundll32.exe'
            else:
                target_name = target.split('\\')[-1]
            rededr = RedEdrAnalyzer(self.config)
            if not rededr.start_tool(target_name):
                self.logger.error("Failed to start RedEdr")
                results['rededr'] = {'status': 'error', 'error': 'Failed to start tool'}
                return None

            ready_start = time.monotonic()
            rededr.wait_for_ready()
            elapsed = time.monotonic() - ready_start
            if rededr.is_ready():
                self.logger.debug(
                    f"RedEdr ready in {elapsed:.2f}s (ETW providers attached)"
                )
                return rededr

            # Reader thread unblocked because RedEdr exited before signaling
            # readiness. Capture whatever output we collected for diagnostics.
            self.logger.error(
                f"RedEdr exited after {elapsed:.2f}s without signaling readiness"
            )
            try:
                rededr.cleanup()
            except Exception:
                pass
            tail = '\n'.join(rededr.collected_output[-20:]) if rededr.collected_output else ''
            results['rededr'] = {
                'status': 'error',
                'error': 'RedEdr exited before ETW providers attached',
                'last_output': tail,
            }
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
        """Create and validate new process. DLL targets are wrapped with
        rundll32.exe — Windows can't directly Popen a .dll, and the
        operator's first cmd_arg is treated as the exported entry point
        (mandatory for DLLs)."""
        if target.lower().endswith('.dll'):
            if not cmd_args:
                raise Exception(
                    "DLL execution requires an entry point as the first "
                    "command-line argument (rundll32 syntax: <ExportName> "
                    "[args...])"
                )
            entry, *extra = cmd_args
            # rundll32.exe expects: <dll>,<entry> [args...]
            # The dll path and entry name are joined with a comma into a
            # single argv slot so rundll32 parses them as one target spec.
            command = ['rundll32.exe', f'{target},{entry}', *extra]
            self.logger.debug(f"DLL target — wrapping with rundll32: {command}")
        else:
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
                raise Exception("Process terminated during initialization")
                
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