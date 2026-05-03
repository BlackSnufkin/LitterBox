# app/analyzers/blender.py
# https://www.forrest-orr.net/post/masking-malicious-memory-artifacts-part-ii-insights-from-moneta

import os
import logging
import glob
import json
import re
from typing import Optional
from datetime import datetime
from .dynamic.moneta_analyzer import MonetaAnalyzer
from .dynamic.hsb_analyzer import HSBAnalyzer
from .dynamic.hollows_hunter_analyzer import HollowsHunterAnalyzer

class BlenderAnalyzer:
    def __init__(self, config: dict, logger: Optional[logging.Logger] = None):
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self.logger.debug("Initializing BlenderAnalyzer")
        
        # Set result folders and analysis filename
        self.result_dir = self.config['utils']['result_folder']
        self.analysis_filename = "dynamic_analysis_results.json"
        self.blender_dir = os.path.join(
            self.config['analysis']['doppelganger']['db']['path'],
            self.config['analysis']['doppelganger']['db']['blender']
        )
        
        # Initialize analyzers
        self.analyzers = {
            'moneta': MonetaAnalyzer(config),
            'hsb': HSBAnalyzer(config),
            'hollows_hunter': HollowsHunterAnalyzer(config)
        }

    def trigger_system_scan(self):
        """Trigger full system scan using all analyzers"""
        results = {}
        
        for name, analyzer in self.analyzers.items():
            try:
                self.logger.debug(f"Starting system scan with {name}")
                
                # HollowsHunter needs directory parameter, others use "*"
                if name == 'hollows_hunter':
                    analyzer.analyze(self.config['analysis']['dynamic']['hollows_hunter'].get('scan_dir', '.'))
                else:
                    analyzer.analyze("*")

                results[name] = analyzer.get_results()
            except Exception as e:
                self.logger.error(f"Error in {name} scan: {str(e)}")
                results[name] = {'status': 'error', 'error': str(e)}

        return results

    def parse_moneta_findings(self, findings: dict) -> dict:
        combined_processes = {}
        current_process = None
        current_dll = None
        
        if 'raw_output' in findings:
            for line in findings['raw_output'].split('\n'):
                line = line.strip()
                if not line:
                    continue
                if ' : ' in line and not line.startswith(' '):
                    parts = [p.strip() for p in line.split(' : ')]
                    if len(parts) >= 2:
                        process_name, pid = parts[:2]
                        key = f"{process_name}_{pid}"
                        if key not in combined_processes:
                            combined_processes[key] = {'process_name': process_name, 'pid': pid, 'iocs': []}
                        current_process = combined_processes[key]
                        current_dll = None
                # Track DLL
                elif line.startswith('0x') and '|' in line and 'DLL Image' in line:
                    parts = [p.strip() for p in line.split('|')]
                    current_dll = parts[2]
                elif current_process and '|' in line:
                    ioc_patterns = {
                        'Modified Code': 'Modified code',
                        'Unsigned Module': 'Unsigned module',
                        'Missing PEB Module': 'Missing PEB module',
                        'Mismatching PEB Module': 'Mismatching PEB module',
                        'Modified PE Header': 'Modified PE header',
                        'Inconsistent Execution': 'Inconsistent +x between disk and memory',
                        'Abnormal Mapped Executable': 'Abnormal mapped executable memory',
                        'Phantom Image': 'Phantom image',
                        'Abnormal Private Executable': 'Abnormal private executable memory',
                        'Non-Image Thread': 'Thread within non-image memory region',
                        'Non-Image Base': 'Non-image primary image base'
                    }
                    for ioc_type, pattern in ioc_patterns.items():
                        if pattern in line:
                            ioc_info = {
                                'type': ioc_type, 
                                'description': line
                            }
                            if current_dll:
                                ioc_info['dll'] = current_dll
                            current_process['iocs'].append(ioc_info)
                            break
        return combined_processes

    def parse_hsb_findings(self, findings: dict) -> dict:
        combined_processes = {}
        detections = findings.get('detections', [])
        for detection in detections:
            process_name, pid = detection['process_name'], str(detection['pid'])
            key = f"{process_name}_{pid}"
            if key not in combined_processes:
                combined_processes[key] = {'process_name': process_name, 'pid': pid, 'iocs': []}
            for finding in detection.get('findings', []):
                ioc = {'type': finding.get('type', ''), 'description': finding.get('description', '')}
                if 'severity' in finding:
                    ioc['severity'] = finding['severity']
                combined_processes[key]['iocs'].append(ioc)
        return combined_processes

    def parse_process_scanner_findings(self, results: dict, scanner_type: str) -> dict:
        """Parse process scanner results (PE-sieve or HollowsHunter)"""
        combined_processes = {}
        detection_mapping = {
            'replaced': ('Process Replacement', 'Process image was replaced', 'HIGH'),
            'hdr_modified': ('Header Modification', 'PE header was modified', 'MEDIUM'),
            'hdrs_modified': ('Header Modification', 'PE header was modified', 'MEDIUM'),  # PE-sieve variant
            'patched': ('Code Patching', 'Process memory was patched', 'MEDIUM'),
            'hooked': ('Code Hooking', 'Process memory was hooked', 'MEDIUM'),
            'iat_hooked': ('IAT Hooking', 'Import Address Table was hooked', 'MEDIUM'),
            'iat_hooks': ('IAT Hooking', 'Import Address Table was hooked', 'MEDIUM'),  # PE-sieve variant
            'implanted_pe': ('PE Implant', 'PE module was implanted', 'HIGH'),
            'implanted_shc': ('Shellcode', 'Shellcode was detected', 'HIGH'),
            'unreachable_file': ('Unreachable File', 'Process file is unreachable', 'MEDIUM'),
            'unreachable': ('Unreachable File', 'Process file is unreachable', 'MEDIUM'),  # PE-sieve variant
            'other': ('Other Anomaly', 'Other suspicious modification detected', 'MEDIUM')
        }

        if scanner_type == 'pe_sieve':
            if results.get('status') == 'completed' and 'findings' in results:
                findings = results['findings']
                pid = None
                process_name = None
                
                if 'raw_output' in findings:
                    for line in findings['raw_output'].split('\n'):
                        if line.startswith('PID:'):
                            pid = line.split(':')[1].strip()
                        # Look for the first scanned file which should be the main process
                        elif '[*] Scanning:' in line:
                            path = line.split('Scanning:')[1].strip()
                            process_name = os.path.basename(path)  # Get filename from path
                            break
                    
                    if pid:
                        process_key = f"{process_name}_{pid}" if process_name else f"unknown_{pid}"
                        combined_processes[process_key] = {
                            'process_name': process_name or 'unknown',
                            'pid': pid,
                            'iocs': []
                        }
                    
                    # Check each detection type
                    for detection_type, (ioc_type, desc_template, severity) in detection_mapping.items():
                        count = findings.get(detection_type, 0)
                        if count > 0:
                            combined_processes[process_key]['iocs'].append({
                                'type': ioc_type,
                                'description': f"{desc_template} ({count} instances)",
                                'severity': severity,
                                'scanner': 'pe_sieve'
                            })

        elif scanner_type == 'hollows_hunter':
            if results.get('status') == 'completed':
                for process in results.get('suspicious', []):
                    if not process:
                        continue
                    
                    process_name = process.get('name')
                    pid = str(process.get('pid', ''))
                    if not process_name or not pid:
                        continue
                    
                    key = f"{process_name}_{pid}"
                    if key not in combined_processes:
                        combined_processes[key] = {
                            'process_name': process_name,
                            'pid': pid,
                            'iocs': []
                        }

                    for detection_type, (ioc_type, desc_template, severity) in detection_mapping.items():
                        count = process.get(detection_type, 0)
                        if count > 0:
                            combined_processes[key]['iocs'].append({
                                'type': ioc_type,
                                'description': f"{desc_template} ({count} instances)",
                                'severity': severity,
                                'scanner': 'hollows_hunter'
                            })

        return combined_processes

    def take_system_sample(self):
        """Parse results from all scanners and combine IOCs per process"""
        scan_results = self.trigger_system_scan()
        combined_processes = {}

        # --- Parse Moneta results ---
        moneta_results = scan_results.get('moneta', {})
        if moneta_results.get('status') == 'completed' and 'findings' in moneta_results:
            moneta_processes = self.parse_moneta_findings(moneta_results['findings'])
            combined_processes.update(moneta_processes)

        # --- Parse HSB results ---
        hsb_results = scan_results.get('hsb', {})
        if hsb_results.get('status') == 'completed' and 'findings' in hsb_results:
            hsb_processes = self.parse_hsb_findings(hsb_results['findings'])
            for key, process in hsb_processes.items():
                if key in combined_processes:
                    combined_processes[key]['iocs'].extend(process['iocs'])
                else:
                    combined_processes[key] = process

        # --- Parse HollowsHunter results ---
        hollows_results = scan_results.get('hollows_hunter', {})
        if hollows_results.get('status') == 'completed':
            hollows_processes = self.parse_process_scanner_findings(hollows_results, 'hollows_hunter')
            for key, process in hollows_processes.items():
                if key in combined_processes:
                    combined_processes[key]['iocs'].extend(process['iocs'])
                else:
                    combined_processes[key] = process

        # --- Finalize and save results ---
        result_list = list(combined_processes.values())
        sanitized_json = json.dumps(result_list, indent=4, ensure_ascii=False)

        date_str = datetime.now().strftime("%m%d%Y")
        file_name = f"BlenderScan_{date_str}.json"
        file_path = os.path.join(self.blender_dir, file_name)

        with open(file_path, 'w', encoding='utf-8') as out_file:
            out_file.write(sanitized_json)

        self.logger.info(f"Blender results saved to: {file_path}")
        self.logger.debug(f"Final JSON Output: {sanitized_json}")
        
        return sanitized_json

    def _extract_instance_count(self, description: str) -> int:
        """Extract instance count from IOC description"""
        if '(' not in description or ')' not in description:
            return 0
            
        try:
            # Look for patterns like "(7 instances)" or "(2 instances)"
            match = re.search(r'\((\d+)\s+instances?\)', description)
            if match:
                return int(match.group(1))
        except:
            pass
        return 0
        
    def _normalize_description(self, description: str) -> str:
        """Remove memory addresses and normalize description for comparison"""
        # Remove memory addresses (patterns like 0x[0-9A-F]+)
        desc = re.sub(r'0x[0-9A-Fa-f]+', '', description)
        
        # Remove sizes after colons (patterns like :0x[0-9A-F]+)
        desc = re.sub(r':[0-9A-Fa-f]+', '', desc)
        
        # Remove instance counts
        desc = re.sub(r'\(\d+\s+instances?\)', '', desc)
        
        # Remove file paths
        desc = re.sub(r'[A-Za-z]:\\[^\s|]*', '', desc)
        
        # Remove extra whitespace and normalize it
        desc = ' '.join(desc.split())
        
        return desc
        
    def compare_processes(self, payload_processes: list, system_processes: list) -> list:
        """Compare payload processes with system processes focusing purely on IOC patterns"""
        matches = []
        
        if isinstance(system_processes, str):
            system_processes = json.loads(system_processes)
            
        self.logger.debug(f"Comparing {len(payload_processes)} payload processes against {len(system_processes)} system processes")
            
        for payload_proc in payload_processes:
            self.logger.debug(f"Analyzing payload process: {payload_proc['process_name']} (PID: {payload_proc['pid']})")
            
            # Group payload IOCs by DLL
            payload_iocs_by_dll = {}
            for ioc in payload_proc['iocs']:
                dll = ioc.get('dll', 'process')  # use 'process' if no DLL specified
                if dll not in payload_iocs_by_dll:
                    payload_iocs_by_dll[dll] = []
                payload_iocs_by_dll[dll].append(ioc)
            
            proc_matches = []
            for sys_proc in system_processes:
                #self.logger.debug(f"Checking against system process: {sys_proc['process_name']} (PID: {sys_proc['pid']})")
                
                # Group system IOCs by DLL
                sys_iocs_by_dll = {}
                for ioc in sys_proc['iocs']:
                    dll = ioc.get('dll', 'process')
                    if dll not in sys_iocs_by_dll:
                        sys_iocs_by_dll[dll] = []
                    sys_iocs_by_dll[dll].append(ioc)
                
                # Compare IOCs
                matching_iocs = []
                total_matches = 0
                dll_match_details = {}
                
                for dll, payload_iocs in payload_iocs_by_dll.items():
                    sys_iocs = sys_iocs_by_dll.get(dll, [])
                    dll_matches = []
                    
                    for p_ioc in payload_iocs:
                        for s_ioc in sys_iocs:
                            if p_ioc['type'] == s_ioc['type']:
                                # Extract instance counts if present
                                p_instances = self._extract_instance_count(p_ioc['description'])
                                s_instances = self._extract_instance_count(s_ioc['description'])

                                # Calculate match score based on instances
                                instance_score = 1.0
                                if p_instances and s_instances:
                                    if p_instances <= s_instances:
                                        instance_score = 1.0  # Full match if payload <= system
                                    else:
                                        instance_score = s_instances / p_instances  # Partial match if payload > system
                                
                                match = {
                                    'type': p_ioc['type'],
                                    'payload_description': p_ioc['description'],
                                    'system_description': s_ioc['description'],
                                    'match_score': instance_score
                                }
                                if 'dll' in p_ioc:
                                    match['dll'] = p_ioc['dll']
                                if 'severity' in p_ioc:
                                    match['severity'] = p_ioc['severity']
                                    
                                dll_matches.append(match)
                                total_matches += 1
                                break
                    
                    if dll_matches:
                        dll_match_details[dll] = {
                            'matches': dll_matches,
                            'match_count': len(dll_matches),
                            'total_iocs': len(payload_iocs)
                        }
                        matching_iocs.extend(dll_matches)
                
                # Calculate match percentage based purely on IOC matches
                if len(payload_proc['iocs']) > 0:
                    match_percentage = (total_matches / len(payload_proc['iocs'])) * 100
                else:
                    match_percentage = 0                
                # Include match if we have any matching IOCs
                if matching_iocs:
                    proc_matches.append({
                        'process_name': sys_proc['process_name'],
                        'pid': sys_proc['pid'],
                        'match_percentage': round(match_percentage, 2),
                        'matching_iocs': matching_iocs,
                        'dll_matches': dll_match_details,
                        'total_matched_iocs': total_matches,
                        'total_system_iocs': len(sys_proc['iocs'])
                    })
            
            if proc_matches:
                # Sort matches by percentage
                proc_matches.sort(key=lambda x: x['match_percentage'], reverse=True)
                matches.append({
                    'payload_process': payload_proc['process_name'],
                    'payload_pid': payload_proc['pid'],
                    'payload_iocs': len(payload_proc['iocs']),
                    'matches': proc_matches
                })
                
                self.logger.debug(f"Found {len(proc_matches)} matching processes for payload {payload_proc['process_name']}")

                    
        return matches

    def compare_payload(self, payload_hash: str):
        """Compare payload against system scan results"""
        try:
            self.logger.debug(f"Comparing payload with hash: {payload_hash}")
            
            # Get payload's analysis results
            result_dir = os.path.join(self.config['utils']['result_folder'], f"{payload_hash}_*", "dynamic_analysis_results.json")
            matching_files = glob.glob(result_dir)


            if not matching_files:
                self.logger.error(f"No analysis results found for payload: {payload_hash}")
                return {
                    "status": "error",
                    "message": "No analysis results found for this payload."
                }

            # Load payload results    
            with open(matching_files[0], 'r') as f:
                payload_results = json.load(f)

            combined_processes = {}
            available_results = []
            
            # Parse Moneta results
            if 'moneta' in payload_results and payload_results['moneta'].get('status') == 'completed':
                available_results.append('moneta')
                self.logger.debug("Parsing Moneta results")
                moneta_processes = self.parse_moneta_findings(payload_results['moneta']['findings'])
                combined_processes.update(moneta_processes)
                
            # Parse HSB results    
            if 'hsb' in payload_results and payload_results['hsb'].get('status') == 'completed':
                available_results.append('hsb')
                self.logger.debug("Parsing HSB results")
                hsb_processes = self.parse_hsb_findings(payload_results['hsb']['findings'])
                for key, process in hsb_processes.items():
                    if key in combined_processes:
                        combined_processes[key]['iocs'].extend(process['iocs'])
                    else:
                        combined_processes[key] = process
                        
            if 'pe_sieve' in payload_results and payload_results['pe_sieve'].get('status') == 'completed':
                available_results.append('pe_sieve')
                pe_sieve_processes = self.parse_process_scanner_findings(payload_results['pe_sieve'], 'pe_sieve')
                for key, process in pe_sieve_processes.items():
                    if key in combined_processes:
                        combined_processes[key]['iocs'].extend(process['iocs'])
                    else:
                        combined_processes[key] = process



            # Get the latest system scan
            blender_dir = self.blender_dir
            system_scans = [f for f in os.listdir(blender_dir) if f.startswith("BlenderScan_")]
           
            if not system_scans:
                self.logger.error("No system scan results available")
                return {
                    "status": "error",
                    "message": "No system scan results available. Please run a system scan first."
                }
               
            latest_scan = max(system_scans, key=lambda x: os.path.getmtime(os.path.join(blender_dir, x)))
            self.logger.debug(f"Using system scan results from: {latest_scan}")
           
            with open(os.path.join(blender_dir, latest_scan), 'r') as f:
                system_processes = json.load(f)
               
            # Parse payload results
            payload_processes = list(combined_processes.values())
           
            # Compare and get matches
            matches = self.compare_processes(payload_processes, system_processes)
           
            result = {
                "status": "success",
                "payload_hash": payload_hash,
                "available_scanners": available_results,
                "payload_processes": payload_processes,
                "matches": matches
            }
           
            return result
           
        except Exception as e:
            self.logger.error(f"Error comparing payload {payload_hash}: {str(e)}")
            return {"error": str(e)}