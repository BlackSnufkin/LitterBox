import subprocess
import json
import threading
import logging
import traceback
from .base import DynamicAnalyzer


# Microsoft-Windows-Kernel-Audit-API-Calls — the task name in the JSON is just
# "Info" so we map etw_event_id → API name. RedEdr subscribes to ids {3,4,5,6}
# (RedEdr/etwreader.cpp:320).
_AUDIT_API_BY_ID = {
    3: 'CreateSymbolicLink',
    4: 'SetContextThread',
    5: 'OpenProcess',
    6: 'OpenThread',
}


# Microsoft-Antimalware-Engine emits "Behavior Monitoring Bm*" events.
# Three categories with different operator value:
#   - Bm* "scan activity" (BmModuleLoad, BmNotificationHandleStart/Stop,
#     BmOpenProcess) — Defender's behavior monitor actively engaging with
#     our process. Count is signal: "Defender scanned the binary N times."
#   - Bm* "internal state" (BmInternal, BmEtw) — Defender's own telemetry
#     plumbing; not signal, hide by default.
#   - Threat verdict events (ThreatFound, MalwareFound, etc.) or any event
#     carrying a non-empty verdict field — actual detection.
_DEFENDER_INTERNAL_SUBSTRINGS = (
    'bminternal',
    'bmetw',
)

_DEFENDER_SCAN_SUBSTRINGS = (
    'bmmoduleload',
    'bmnotificationhandle',
    'bmopenprocess',
)


# Substrings that indicate a real Defender detection (not just monitoring).
_DEFENDER_THREAT_SUBSTRINGS = (
    'threatfound',
    'threatdetect',
    'detectionadded',
    'malwarefound',
    'protectionalert',
    'detected',
)


def _classify_defender_event(event_name, verdict):
    """Return one of 'threat' / 'scan' / 'internal' / 'other'."""
    if _is_defender_threat(event_name, verdict):
        return 'threat'
    lowered = (event_name or '').lower()
    if any(s in lowered for s in _DEFENDER_INTERNAL_SUBSTRINGS):
        return 'internal'
    if any(s in lowered for s in _DEFENDER_SCAN_SUBSTRINGS):
        return 'scan'
    return 'other'


def _is_defender_threat(event_name, verdict):
    if verdict and isinstance(verdict, str) and verdict.strip():
        return True
    if event_name:
        lowered = event_name.lower()
        if any(s in lowered for s in _DEFENDER_THREAT_SUBSTRINGS):
            return True
    return False


class RedEdrAnalyzer(DynamicAnalyzer):
    # Readiness substring emitted by RedEdr.exe via loguru on stderr (which we
    # merge into stdout) once all ETW providers are attached. See
    # RedEdr/etwreader.cpp:431 — "ETW: All providers configured, ready to start
    # collecting". Fires immediately before the threadReadynessEtw event is
    # signaled, so when we observe this line ManagerStart has effectively
    # returned and RedEdr is collecting events.
    _READY_MARKER = 'All providers configured'

    def __init__(self, config):
        super().__init__(config)
        self.tool_process = None
        self.target_name = None
        self.results = {}
        self.collected_output = []
        self._output_lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        self.output_thread = None
        self._stop_reading = threading.Event()
        self._ready_event = threading.Event()

    def _reader_thread(self):
        """Thread to read RedEdr output without blocking.

        Watches every line for the ETW-ready marker so callers can fire the
        payload as soon as RedEdr is actually collecting. The same `_ready_event`
        is also set on EOF (RedEdr exited) so `wait_for_ready()` never hangs
        forever — callers distinguish real readiness from process-death by
        checking `is_ready()`."""
        try:
            while not self._stop_reading.is_set():
                line = self.tool_process.stdout.readline()
                if not line:
                    break  # EOF — process closed stdout (likely exited)

                line = line.strip()
                if line:
                    with self._output_lock:
                        self.collected_output.append(line)
                    if not self._ready_event.is_set() and self._READY_MARKER in line:
                        self._ready_event.set()

        except Exception as e:
            print(f"Error in reader thread: {e}")
        finally:
            # Unblock wait_for_ready() on any reader exit (EOF, exception,
            # stop request) so callers never hang waiting on a dead process.
            self._ready_event.set()

    def wait_for_ready(self):
        """Block until RedEdr signals ETW-providers-attached, or until the
        reader thread exits (process died / pipe closed / stop requested).

        No timeout — RedEdr's normal startup is bounded by ETW provider
        attachment (typically 1-3s) and any failure surfaces as a quick exit
        which trips the EOF path in the reader thread.

        Use `is_ready()` after returning to distinguish real readiness from
        a dead-process unblock."""
        self._ready_event.wait()

    def is_ready(self):
        """True only if the readiness marker was actually seen on stdout."""
        if not self._ready_event.is_set():
            return False
        # Distinguish real readiness from a dead-process unblock by checking
        # the live process. If the subprocess exited before the marker fired,
        # is_ready() must return False so callers can error out cleanly.
        if self.tool_process is None:
            return False
        return self.tool_process.poll() is None
            
    def start_tool(self, target_name):
        """Start the RedEdr tool in monitoring mode"""
        try:
            self.target_name = target_name
            tool_config = self.config['analysis']['dynamic']['rededr']
            command = tool_config['command'].format(
                tool_path=tool_config['tool_path'],
                process_name=target_name
            )
            
            self.tool_process = subprocess.Popen(
                command,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Reset stop flag
            self._stop_reading.clear()
            
            # Start the output reader thread
            self.output_thread = threading.Thread(target=self._reader_thread)
            self.output_thread.daemon = True
            self.output_thread.start()
            
            return True
        except Exception as e:
            self.results = {
                'status': 'error',
                'error': f'Failed to start RedEdr: {str(e)}'
            }
            return False
            
    def analyze(self, pid):
        """Not used for RedEdr"""
        pass
    
    def _parse_output(self, output):
        """Parse RedEdr JSON output into structured data"""
        findings = {
            'events': [],
            'process_info': {
                'commandline': None,
                'image_path': None,
                'working_dir': None,
                'parent_pid': None,
                'is_debugged': False,
                'is_protected_process': False,
                'pid': None,
                'start_time': None  # Add start time field
            },
            'loaded_dlls': [],
            'child_processes': [],
            'threads': [],
            'image_loads': [],
            'image_unloads': [],
            'cpu_priority_changes': [],
            # Categories sourced from additional ETW providers RedEdr taps
            # when launched with --etw / --with-antimalwareengine / --with-defendertrace.
            # ETW field names are lowercased by RedEdr's KrabsEtwEventToJsonStr.
            'file_operations': [],     # Microsoft-Windows-Kernel-File
            'network_activity': [],    # Microsoft-Windows-Kernel-Network
            'audit_api_calls': [],     # Microsoft-Windows-Kernel-Audit-API-Calls
            'defender_events': [],     # Microsoft-Antimalware-Engine + msmpeng track
        }

        try:
            # First pass to find process start time
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue

                if line.startswith('{'):
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                        
                    event_type = event.get('type', '').strip()
                    event_name = event.get('event', '').strip()
                    
                    # Capture process start time from the first ImageLoadInfo of the main process
                    if event_type == 'etw' and event_name == 'ImageLoadInfo' and not findings['process_info']['start_time']:
                        findings['process_info']['start_time'] = event.get('time')

            # Reset and process all events
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue

                if line.startswith('{'):
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    
                    event_type = event.get('type', '').strip()
                    event_name = event.get('event', '').strip()
                    func_name  = event.get('func', '').strip()

                    # Process Query Events
                    if event_type in ['process_query', 'proces_query']:
                        # PEB Info
                        if func_name == 'peb' or event_name == 'peb':
                            findings['process_info'].update({
                                'commandline': event.get('commandline'),
                                'image_path': event.get('image_path'),
                                'working_dir': event.get('working_dir'),
                                'parent_pid': event.get('parent_pid'),
                                'is_debugged': event.get('is_debugged', False),
                                'is_protected_process': event.get('is_protected_process', False),
                                'pid': event.get('pid')
                            })
                        # Loaded DLLs
                        elif func_name == 'loaded_dll':
                            dlls = event.get('dlls', [])
                            event_time = event.get('time')
                            if isinstance(dlls, list):
                                # Add time to each DLL
                                for dll in dlls:
                                    if isinstance(dll, dict):
                                        dll['time'] = event_time
                                findings['loaded_dlls'].extend(dlls)
                            elif isinstance(dlls, dict):
                                dlls['time'] = event_time
                                findings['loaded_dlls'].append(dlls)

                    # ETW Events
                    # Field names emitted by RedEdr are lowercased by
                    # KrabsEtwEventToJsonStr (RedEdrShared/etw_krabs.cpp:55).
                    # Standard fields (etw_pid, etw_tid, etw_time,
                    # etw_provider_name, etw_event_id, event, type, stack_trace)
                    # keep their casing; everything else is lowercased.
                    elif event_type == 'etw':
                        if event.get('etw_pid') and not findings['process_info']['pid']:
                            findings['process_info']['pid'] = event.get('etw_pid')

                        if event_name == 'ProcessStartStart':
                            findings['child_processes'].append({
                                'pid': event.get('processid'),
                                'parent_pid': event.get('parentprocessid'),
                                'image_name': event.get('imagename'),
                                'create_time': event.get('createtime') or event.get('etw_time'),
                            })

                        elif event_name == 'ThreadStartStart':
                            findings['threads'].append({
                                'thread_id': event.get('threadid'),
                                'process_id': event.get('processid'),
                                'start_addr': event.get('startaddr'),
                                'stack_base': event.get('stackbase'),
                            })

                        elif event_name == 'ImageLoadInfo':
                            findings['image_loads'].append({
                                'pid': event.get('processid'),
                                'image_name': event.get('imagename'),
                                'base': event.get('imagebase'),
                                'size': event.get('imagesize'),
                                'time_stamp': event.get('etw_time') or event.get('time'),
                                'stack_trace': event.get('stack_trace', []),
                            })

                        elif event_name == 'ImageUnloadInfo':
                            findings['image_unloads'].append({
                                'pid': event.get('processid'),
                                'image_name': event.get('imagename'),
                                'base': event.get('imagebase'),
                                'size': event.get('imagesize'),
                                'time_stamp': event.get('etw_time') or event.get('time'),
                                'stack_trace': event.get('stack_trace', []),
                            })

                        elif event_name in ['CpuBasePriorityChangeInfo', 'CpuPriorityChangeInfo']:
                            findings['cpu_priority_changes'].append({
                                'pid': event.get('processid'),
                                'thread_id': event.get('threadid'),
                                'old_priority': event.get('oldpriority'),
                                'new_priority': event.get('newpriority'),
                                'time': event.get('etw_time') or event.get('time'),
                            })

                        # ETW provider-based dispatch for the categories the
                        # parser used to ignore. Routes by provider name; field
                        # names are lowercased by RedEdr — try a couple of
                        # likely keys per slot since the ETW manifest varies.
                        provider = event.get('etw_provider_name', '')
                        if provider == 'Microsoft-Windows-Kernel-File':
                            findings['file_operations'].append({
                                'path':       event.get('filename') or event.get('filepath') or event.get('name'),
                                'operation':  event_name,
                                'time':       event.get('etw_time') or event.get('time'),
                                'thread_id':  event.get('etw_tid'),
                                'pid':        event.get('etw_pid'),
                                'stack_trace': event.get('stack_trace', []),
                            })
                        elif provider == 'Microsoft-Windows-Kernel-Network':
                            findings['network_activity'].append({
                                'proto':       'tcp' if 'tcp' in event_name.lower() else ('udp' if 'udp' in event_name.lower() else 'unknown'),
                                'operation':   event_name,
                                'local_addr':  event.get('saddr'),
                                'local_port':  event.get('sport'),
                                'remote_addr': event.get('daddr'),
                                'remote_port': event.get('dport'),
                                'size':        event.get('size'),
                                'time':        event.get('etw_time') or event.get('time'),
                                'pid':         event.get('etw_pid') or event.get('pid'),
                                'stack_trace': event.get('stack_trace', []),
                            })
                        elif provider == 'Microsoft-Windows-Kernel-Audit-API-Calls':
                            # The provider's task name is just "Info" — the
                            # actual API is identified by etw_event_id.
                            # See RedEdr/etwreader.cpp:320 (events 3,4,5,6).
                            api_name = _AUDIT_API_BY_ID.get(
                                event.get('etw_event_id'),
                                event_name or 'Unknown',
                            )
                            findings['audit_api_calls'].append({
                                'api':            api_name,
                                'event_id':       event.get('etw_event_id'),
                                'target_pid':     event.get('targetprocessid'),
                                'target_tid':     event.get('targetthreadid'),
                                'desired_access': event.get('desiredaccess'),
                                'return_code':    event.get('returncode'),
                                'time':           event.get('etw_time') or event.get('time'),
                                'caller_pid':     event.get('etw_pid'),
                                'caller_tid':     event.get('etw_tid'),
                                'stack_trace':    event.get('stack_trace', []),
                            })
                        elif provider == 'Microsoft-Antimalware-Engine':
                            verdict = event.get('threatname') or event.get('threatid') or event.get('result')
                            category = _classify_defender_event(event_name, verdict)
                            findings['defender_events'].append({
                                'provider':    'antimalware_engine',
                                'event':       event_name,
                                'event_id':    event.get('etw_event_id'),
                                'scan_target': event.get('filename') or event.get('name') or event.get('path'),
                                'verdict':     verdict,
                                'severity':    event.get('severityid') or event.get('severity'),
                                'time':        event.get('etw_time') or event.get('time'),
                                'category':    category,
                                'is_threat':   category == 'threat',
                            })
                        elif event.get('etw_process', '').lower() == 'msmpeng.exe':
                            # Captured via --with-defendertrace: msmpeng activity touching our payload.
                            verdict = event.get('threatname') or event.get('threatid') or event.get('result')
                            category = _classify_defender_event(event_name, verdict)
                            findings['defender_events'].append({
                                'provider':    'defender_trace',
                                'event':       event_name,
                                'event_id':    event.get('etw_event_id'),
                                'scan_target': event.get('filename') or event.get('name') or event.get('path'),
                                'verdict':     verdict,
                                'time':        event.get('etw_time') or event.get('time'),
                                'category':    category,
                                'is_threat':   category == 'threat',
                            })

                    # Store all valid JSON events
                    findings['events'].append(event)

        except Exception as e:
            self.logger.error(f"Error parsing output: {e}", exc_info=True)
            return findings

        return findings

    def get_results(self):
        """
        Get all collected events and analysis results from RedEdr.
        Returns a structured dictionary containing process information, events, and statistics.
        """
        try:
            with self._output_lock:
                output_text = '\n'.join(self.collected_output)
                
            # Create a default structure for empty/error cases
            default_findings = {
                'process_info': {
                    'pid': None,
                    'commandline': None,
                    'image_path': None,
                    'working_dir': None,
                    'parent_pid': None,
                    'is_debugged': False,
                    'is_protected_process': False,
                    'integrity_level': 'unknown'
                },
                'loaded_dlls': [],
                'child_processes': [],
                'threads': [],
                'image_loads': [],
                'image_unloads': [],
                'cpu_priority_changes': [],
                'file_operations': [],
                'network_activity': [],
                'audit_api_calls': [],
                'defender_events': [],
                'summary': {
                    'total_events': 0,
                    'total_dlls': 0,
                    'total_child_processes': 0,
                    'total_threads': 0,
                    'total_image_loads': 0,
                    'total_image_unloads': 0,
                    'total_file_operations': 0,
                    'total_network_activity': 0,
                    'total_audit_api_calls': 0,
                    'total_defender_events': 0,
                }
            }

            parsed_data = self._parse_output(output_text)
            
            # If parsing failed, return the default structure
            if parsed_data is None:
                self.logger.warning("Parsing output returned None, using default structure")
                return {
                    'status': 'completed',
                    'findings': default_findings,
                    'raw_output': output_text
                }

            # If we have parsed data, update the default structure with actual values
            findings = default_findings.copy()
            
            # Update process info if available
            if 'process_info' in parsed_data and parsed_data['process_info']:
                findings['process_info'].update({
                    'pid': parsed_data['process_info'].get('pid'),
                    'commandline': parsed_data['process_info'].get('commandline'),
                    'image_path': parsed_data['process_info'].get('image_path'),
                    'working_dir': parsed_data['process_info'].get('working_dir'),
                    'parent_pid': parsed_data['process_info'].get('parent_pid'),
                    'is_debugged': parsed_data['process_info'].get('is_debugged', False),
                    'is_protected_process': parsed_data['process_info'].get('is_protected_process', False)
                })

            # Update lists with actual data if available
            for key in ('loaded_dlls', 'child_processes', 'threads',
                        'image_loads', 'image_unloads', 'cpu_priority_changes',
                        'file_operations', 'network_activity',
                        'audit_api_calls', 'defender_events'):
                if key in parsed_data:
                    findings[key] = parsed_data[key]

            # Per-provider event counts (diagnostic). Surfaces whether ETW
            # actually delivered events from each provider RedEdr subscribes
            # to. A 0 count for Microsoft-Windows-Kernel-Network when the
            # payload made TCP connections almost always means the events
            # fired but were attributed to System(4) / svchost rather than
            # the payload PID — which RedEdr's event_callback_process drops.
            # Reliable network capture would require RedEdr's --hook mode
            # (kernel driver + DLL injection).
            events_by_provider = {}
            for ev in parsed_data.get('events', []):
                provider = ev.get('etw_provider_name') or ev.get('type') or 'unknown'
                events_by_provider[provider] = events_by_provider.get(provider, 0) + 1

            # Update summary
            findings['summary'] = {
                'total_events': len(parsed_data.get('events', [])),
                'total_dlls': len(findings['loaded_dlls']),
                'total_child_processes': len(findings['child_processes']),
                'total_threads': len(findings['threads']),
                'total_image_loads': len(findings['image_loads']),
                'total_image_unloads': len(findings['image_unloads']),
                'total_file_operations': len(findings['file_operations']),
                'total_network_activity': len(findings['network_activity']),
                'total_audit_api_calls': len(findings['audit_api_calls']),
                'total_defender_events': len(findings['defender_events']),
                'events_by_provider': events_by_provider,
            }

            findings['timeline'] = self._generate_timeline(findings)

            return {
                'status': 'completed',
                'findings': findings,
                'raw_output': output_text
            }
                
        except Exception as e:
            self.logger.error(f"Error in get_results: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e),
                'error_details': {
                    'type': type(e).__name__,
                    'traceback': traceback.format_exc()
                },
                'findings': default_findings
            }

    @staticmethod
    def _module_basename(path):
        """Strip kernel device prefixes / directories down to a basename.
        e.g. '\\Device\\HarddiskVolume3\\Windows\\System32\\cryptsp.dll' -> 'cryptsp.dll'."""
        if not path:
            return ''
        return path.replace('/', '\\').rsplit('\\', 1)[-1]

    def _generate_timeline(self, parsed_data):
        """
        Generate a chronological timeline of significant events.

        Module loads are de-duplicated across two sources that report the same
        thing differently:
          - ETW Microsoft-Windows-Kernel-Process ImageLoad events (one per
            actual load, with real per-event timestamps and full kernel paths)
          - The PEB-walk snapshot RedEdr emits when it first augments the
            target (one event with all currently-loaded modules)

        We trust ETW first (better timing) and only fall back to PEB entries
        whose basename ETW didn't see. That covers the rare case where RedEdr
        attaches AFTER the target has already loaded some modules.
        """
        timeline = []

        # Add process start if available
        if parsed_data.get('process_info', {}).get('pid'):
            timeline.append({
                'time': None,  # We don't have start time in current data
                'type': 'Process Start',
                'details': f"Process started: PID {parsed_data['process_info']['pid']}"
            })

        # Add child process creations
        for child in parsed_data.get('child_processes', []):
            timeline.append({
                'time': child.get('create_time', None),
                'type': 'Child Process',
                'details': f"Created child process: {child.get('image_name', 'Unknown')} (PID: {child.get('pid', 'Unknown')})"
            })

        # ETW image loads — primary source for module-load timeline entries.
        seen_basenames = set()
        for img in parsed_data.get('image_loads', []):
            raw = img.get('image_name') or 'Unknown'
            basename = self._module_basename(raw) or raw
            seen_basenames.add(basename.lower())
            timeline.append({
                'time': img.get('time_stamp', None),
                'type': 'Image Load',
                'details': f"Loaded image: {basename}",
            })

        # PEB snapshot DLLs — only add ones ETW didn't already see, since the
        # snapshot is largely redundant with ETW for any process that started
        # under RedEdr's watch.
        for dll in parsed_data.get('loaded_dlls', []):
            name = dll.get('name') or ''
            basename = self._module_basename(name) or name
            if basename.lower() in seen_basenames:
                continue
            seen_basenames.add(basename.lower())
            timeline.append({
                'time': dll.get('time', None),
                'type': 'DLL Load',
                'details': f"Loaded DLL: {basename} (initial)",
            })

        # Sort timeline by timestamp if available, otherwise keep original order
        # Filter out None timestamps and put them at the start
        timeline_with_time = [x for x in timeline if x['time'] is not None]
        timeline_without_time = [x for x in timeline if x['time'] is None]
        
        # Sort only events with timestamps
        timeline_with_time.sort(key=lambda x: str(x['time']))
        
        # Combine the lists, putting events without timestamps first
        sorted_timeline = timeline_without_time + timeline_with_time
        
        return sorted_timeline

    def cleanup(self):
        """Stop the RedEdr process if it's still running.

        Idempotent — safe to call multiple times. Manager calls this in a
        try/finally so it can fire after the happy-path cleanup or after a
        crashed payload's exception path."""
        # Signal reader thread to stop
        self._stop_reading.set()

        if self.tool_process is None:
            return

        proc = self.tool_process
        self.tool_process = None  # Mark cleaned up before any I/O — second
                                  # call sees None and returns immediately.
        try:
            proc.terminate()
            proc.wait(timeout=5)

            # Wait for reader thread to finish
            if self.output_thread and self.output_thread.is_alive():
                self.output_thread.join(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception as e:
            self.logger.warning(f"RedEdr cleanup: error while stopping subprocess: {e}")
        finally:
            try:
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
            except Exception:
                pass