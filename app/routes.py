# app/routes.py

import datetime
import glob
import json
import os
import shutil
from datetime import datetime
from functools import wraps
from flask import render_template, request, jsonify, Response, redirect
from .utils import Utils
from .analyzers.manager import AnalysisManager
from .analyzers.blender import BlenderAnalyzer
from .analyzers.fuzzy import FuzzyHashAnalyzer
from .analyzers.holygrail import HolyGrailAnalyzer

class RouteHelpers:
    """Centralized helper class to eliminate code duplication across routes"""
    
    def __init__(self, app_config, logger):
        self.config = app_config
        self.logger = logger
        self.utils = Utils(app_config)
    
    def load_analysis_data(self, target):
        """Unified method to load analysis data for both files and PIDs"""
        is_pid = target.isdigit()
        
        if is_pid:
            return self._load_pid_data(target)
        else:
            return self._load_file_data(target)
    
    def _load_pid_data(self, pid):
        """Load analysis data for PID-based analysis"""
        is_valid, error_msg = self.utils.validate_pid(pid)
        if not is_valid:
            return None, error_msg, True
        
        result_folder = os.path.join(self.config['utils']['result_folder'], f'dynamic_{pid}')
        if not os.path.exists(result_folder):
            return None, f'Process with PID {pid} does not exist', True
        
        dynamic_path = os.path.join(result_folder, 'dynamic_analysis_results.json')
        if not os.path.exists(dynamic_path):
            return None, f'Dynamic analysis results for PID {pid} not found', True
        
        dynamic_results = self.utils.load_json_file(dynamic_path)
        if not dynamic_results:
            return None, 'Error loading dynamic analysis results', True
        
        return {
            'is_pid': True,
            'pid': pid,
            'result_path': result_folder,
            'file_info': None,
            'static_results': None,
            'dynamic_results': dynamic_results
        }, None, False
    
    def _load_file_data(self, file_hash):
        """Load analysis data for file-based analysis"""
        result_path = self.utils.find_file_by_hash(file_hash, self.config['utils']['result_folder'])
        if not result_path:
            return None, 'Results not found', True
        
        file_info_path = os.path.join(result_path, 'file_info.json')
        if not os.path.exists(file_info_path):
            return None, 'File info not found', True
        
        file_info = self.utils.load_json_file(file_info_path)
        if not file_info:
            return None, 'Error loading file info', True
        
        static_path = os.path.join(result_path, 'static_analysis_results.json')
        dynamic_path = os.path.join(result_path, 'dynamic_analysis_results.json')
        
        static_results = self.utils.load_json_file(static_path) if os.path.exists(static_path) else None
        dynamic_results = self.utils.load_json_file(dynamic_path) if os.path.exists(dynamic_path) else None
        
        return {
            'is_pid': False,
            'pid': None,
            'result_path': result_path,
            'file_info': file_info,
            'static_results': static_results,
            'dynamic_results': dynamic_results
        }, None, False
    
    def calculate_and_add_risk(self, data):
        """Calculate risk assessment and add to data"""
        if data['is_pid']:
            risk_score, risk_factors = self.utils.calculate_risk(
                analysis_type='process',
                dynamic_results=data['dynamic_results']
            )
        else:
            risk_score, risk_factors = self.utils.calculate_risk(
                analysis_type='file',
                file_info=data['file_info'],
                static_results=data['static_results'],
                dynamic_results=data['dynamic_results']
            )
        
        risk_level = self.utils.get_risk_level(risk_score)
        
        risk_data = {
            'score': risk_score,
            'level': risk_level,
            'factors': risk_factors
        }
        
        if data['is_pid'] and data['dynamic_results']:
            data['dynamic_results']['risk_assessment'] = risk_data
        elif data['file_info']:
            data['file_info']['risk_assessment'] = risk_data
        
        return risk_score, risk_level, risk_factors
    
    def get_detection_counts(self, data):
        """Get detection counts from analysis results"""
        results = data['dynamic_results'] or data['static_results'] or {}
        return self.utils.extract_detection_counts(results)

    def save_analysis_results(self, results, result_path, results_filename):
        """Save analysis results to file"""
        results_file_path = os.path.join(result_path, results_filename)
        with open(results_file_path, 'w') as f:
            json.dump(results, f)
        self.logger.debug(f"Analysis results saved to: {results_file_path}")
        return results_file_path

    def process_file_cleanup(self, folders_to_clean):
        """Process cleanup for multiple folders"""
        results = {'uploads_cleaned': 0, 'analysis_cleaned': 0, 'result_cleaned': 0, 'errors': []}
        
        for folder_type, folder_path in folders_to_clean.items():
            if not os.path.exists(folder_path):
                continue
                
            try:
                if folder_type == 'uploads':
                    results['uploads_cleaned'] += self._clean_files_in_folder(folder_path)
                elif folder_type == 'results':
                    results['result_cleaned'] += self._clean_folders_in_folder(folder_path)
                elif folder_type == 'analysis':
                    results['analysis_cleaned'] += self._clean_process_folders(folder_path)
            except Exception as e:
                self.logger.error(f"Error cleaning {folder_type}: {e}")
                results['errors'].append(f"Error cleaning {folder_type}: {str(e)}")
        
        return results

    def _clean_files_in_folder(self, folder_path):
        """Clean files in a folder"""
        count = 0
        for f in os.listdir(folder_path):
            file_path = os.path.join(folder_path, f)
            if os.path.isfile(file_path):
                os.unlink(file_path)
                count += 1
        return count

    def _clean_folders_in_folder(self, folder_path):
        """Clean folders in a folder"""
        count = 0
        for f in os.listdir(folder_path):
            full_path = os.path.join(folder_path, f)
            if os.path.isdir(full_path):
                shutil.rmtree(full_path)
                count += 1
        return count

    def _clean_process_folders(self, analysis_path):
        """Clean process-specific analysis folders"""
        count = 0
        process_folders = glob.glob(os.path.join(analysis_path, 'process_*'))
        for folder in process_folders:
            shutil.rmtree(folder)
            count += 1
        return count


def error_handler(f):
    """Decorator for consistent error handling across all routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            # Get app from context
            from flask import current_app
            current_app.logger.error(f"Error in {f.__name__}: {e}")
            current_app.logger.error("Traceback:", exc_info=True)
            return jsonify({'error': str(e)}), 500
    return decorated_function


def register_routes(app):
    analysis_manager = AnalysisManager(app.config, logger=app.logger)
    route_helpers = RouteHelpers(app.config, app.logger)
    utils = route_helpers.utils

    @app.route('/')
    def index():
        return render_template('upload.html', config=app.config)

    @app.route('/upload', methods=['POST'])
    @error_handler
    def upload_file():
        app.logger.debug("Received a file upload request.")
        
        if 'file' not in request.files:
            app.logger.debug("No file part in the request.")
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            app.logger.debug("No file selected for upload.")
            return jsonify({'error': 'No selected file'}), 400
        
        if not (file and utils.allowed_file(file.filename)):
            app.logger.debug(f"File type of '{file.filename}' is not allowed.")
            return jsonify({'error': 'File type not allowed'}), 400
        
        app.logger.debug(f"File '{file.filename}' is allowed. Attempting to save.")
        file_info = utils.save_uploaded_file(file)
        app.logger.debug(f"File '{file.filename}' uploaded and saved successfully.")
        return jsonify({
            'message': 'File uploaded successfully',
            'file_info': file_info
        }), 200

    @app.route('/validate/<pid>', methods=['POST'])
    @error_handler
    def validate_process(pid):
        app.logger.debug(f"Received PID validation request for PID: {pid}")
        
        is_valid, error_msg = utils.validate_pid(pid)
        if not is_valid:
            app.logger.debug(f"PID {pid} is invalid. Reason: {error_msg}")
            return jsonify({'error': error_msg}), 404

        app.logger.debug(f"PID {pid} is valid.")
        return jsonify({'status': 'valid'}), 200

    @app.route('/analyze/<analysis_type>/<target>', methods=['GET', 'POST'])
    @error_handler
    def analyze_file(analysis_type, target):
        app.logger.debug(f"Received request to analyze. Analysis type: {analysis_type}, Target: {target}")
        
        if request.method == 'GET':
            app.logger.debug(f"GET request received for analysis type: {analysis_type}, Target: {target}")
            return render_template('results.html', analysis_type=analysis_type, file_hash=target)

        app.logger.debug(f"POST request received. Performing {analysis_type} analysis.")
        is_pid = analysis_type == 'dynamic' and target.isdigit()
        
        if is_pid:
            return _perform_pid_analysis(target, analysis_manager, route_helpers, app)
        else:
            return _perform_file_analysis(analysis_type, target, analysis_manager, route_helpers, app)

    def _perform_pid_analysis(pid, analysis_manager, route_helpers, app):
        is_valid, error_msg = route_helpers.utils.validate_pid(pid)
        if not is_valid:
            app.logger.debug(f"PID validation failed for PID {pid}. Reason: {error_msg}")
            return jsonify({'error': error_msg}), 404

        result_folder = os.path.join(route_helpers.config['utils']['result_folder'], f'dynamic_{pid}')
        os.makedirs(result_folder, exist_ok=True)
        
        cmd_args = _extract_and_validate_args(request, app.logger)
        
        app.logger.debug(f"Performing dynamic analysis on PID: {pid}")
        results = analysis_manager.run_dynamic_analysis(pid, True, cmd_args)
        
        return _handle_analysis_results(results, result_folder, 'dynamic_analysis_results.json', route_helpers, app)

    def _perform_file_analysis(analysis_type, target, analysis_manager, route_helpers, app):
        if analysis_type == 'static' and target.isdigit():
            app.logger.debug(f"Static analysis requested on PID {target}. This is invalid.")
            return jsonify({'error': 'Cannot perform static analysis on PID'}), 400
        
        if analysis_type not in ['static', 'dynamic']:
            app.logger.debug(f"Invalid analysis type received: {analysis_type}")
            return jsonify({'error': 'Invalid analysis type'}), 400
        
        file_path = route_helpers.utils.find_file_by_hash(target, app.config['utils']['upload_folder'])
        result_path = route_helpers.utils.find_file_by_hash(target, app.config['utils']['result_folder'])
        
        if not file_path:
            app.logger.debug(f"File with hash {target} not found in upload folder.")
            return jsonify({'error': 'File not found'}), 404
        
        app.logger.debug(f"File found at: {file_path}, Results will be saved to: {result_path}")
        
        if analysis_type == 'static':
            app.logger.debug(f"Performing static analysis on file: {file_path}")
            results = analysis_manager.run_static_analysis(file_path)
            results_file = 'static_analysis_results.json'
        else:
            cmd_args = _extract_and_validate_args(request, app.logger)
            app.logger.debug(f"Performing dynamic analysis on target: {file_path}, is_pid: False")
            results = analysis_manager.run_dynamic_analysis(file_path, False, cmd_args)
            results_file = 'dynamic_analysis_results.json'
        
        return _handle_analysis_results(results, result_path, results_file, route_helpers, app)

    def _extract_and_validate_args(request, logger):
        try:
            request_data = request.get_json() or {}
            cmd_args = request_data.get('args', [])
            
            if not isinstance(cmd_args, list):
                logger.error("Invalid arguments format provided")
                return []
            
            for arg in cmd_args:
                if not isinstance(arg, str):
                    logger.error("Non-string argument provided")
                    return []
                if any(char in arg for char in ';&|'):
                    logger.error("Potentially dangerous argument detected")
                    return []
            
            logger.debug(f"Command line arguments received: {cmd_args}")
            return cmd_args
        except Exception as e:
            logger.error(f"Error parsing request data: {e}")
            return []

    def _handle_analysis_results(results, result_path, results_filename, route_helpers, app):
        route_helpers.save_analysis_results(results, result_path, results_filename)
        
        if results.get('status') == 'early_termination':
            app.logger.error("Process terminated early during initialization")
            return jsonify({
                'status': 'early_termination',
                'error': results.get('error', {}).get('message', 'Process terminated early'),
                'details': {
                    'termination_time': results.get('error', {}).get('termination_time'),
                    'init_time': results.get('error', {}).get('init_time'),
                    'message': results.get('error', {}).get('details')
                }
            }), 202
        
        if results.get('status') == 'error':
            app.logger.debug("Analysis completed with errors.")
            return jsonify({
                'status': 'error',
                'error': results.get('error', {}).get('message', 'Analysis failed'),
                'details': results.get('error', {}).get('details')
            }), 500
        
        app.logger.debug("Analysis completed successfully.")
        return jsonify({'status': 'success', 'results': results})

    @app.route('/results/<target>/<analysis_type>', methods=['GET'])
    @error_handler
    def get_analysis_results(target, analysis_type):
        app.logger.debug(f"Received analysis results request for target: {target}, analysis_type: {analysis_type}")
        
        data, error_msg, is_error = route_helpers.load_analysis_data(target)
        if is_error:
            app.logger.debug(f"Error loading data: {error_msg}")
            return render_template('error.html', error=error_msg), 404
        
        risk_score, risk_level, risk_factors = route_helpers.calculate_and_add_risk(data)
        app.logger.debug(f"Calculated risk assessment - Score: {risk_score}, Level: {risk_level}")
        
        if data['is_pid']:
            return _render_pid_results(data, route_helpers, app)
        else:
            return _render_file_results(data, analysis_type, route_helpers, app)

    def _render_pid_results(data, route_helpers, app):
        detections = route_helpers.get_detection_counts(data)
        app.logger.debug(f"Extracted detection counts: {detections}")
        
        risk_data = data['dynamic_results']['risk_assessment']
        return render_template(
            'dynamic_info.html',
            file_info=None,
            analysis_results=data['dynamic_results'],
            yara_detections=detections['yara'],
            pesieve_detections=detections['pesieve'],
            moneta_detections=detections['moneta'],
            patriot_detections=detections['patriot'],
            hsb_detections=detections['hsb'],
            risk_level=risk_data['level'],
            risk_score=risk_data['score'],
            risk_factors=risk_data['factors']
        )

    def _render_file_results(data, analysis_type, route_helpers, app):
        if analysis_type == 'info':
            return _render_file_info(data, utils, app)
        elif analysis_type == 'byovd':
            return _render_byovd_results(data, route_helpers, app)
        elif analysis_type in ['static', 'dynamic']:
            return _render_analysis_info(data, analysis_type, route_helpers, app)
        else:
            app.logger.debug(f"Invalid analysis type received: {analysis_type}")
            return render_template('error.html', error='Invalid analysis type.'), 400

    def _render_byovd_results(data, route_helpers, app):
        """Render driver-specific BYOVD analysis results"""
        app.logger.debug("Rendering BYOVD (driver) results")
        
        # Check if this is actually a driver file
        file_info = data['file_info']
        filename = file_info.get('original_name', '')
        if not _is_kernel_driver_file(filename):
            app.logger.warning(f"BYOVD analysis requested for non-driver file: {filename}")
            return render_template('error.html', error='BYOVD analysis is only available for driver files (.sys)'), 400
        
        # Load HolyGrail results
        result_path = data['result_path']
        holygrail_path = os.path.join(result_path, 'byovd_results.json')
        
        holygrail_results = None
        if os.path.exists(holygrail_path):
            holygrail_results = route_helpers.utils.load_json_file(holygrail_path)
            app.logger.debug(f"Loaded HolyGrail results from: {holygrail_path}")
        else:
            app.logger.debug(f"No HolyGrail results found at: {holygrail_path}")
        
        app.logger.debug("Rendering byovd_info.html template")
        return render_template(
            'byovd_info.html',
            file_info=file_info,
            holygrail_results=holygrail_results,
            has_holygrail_analysis=holygrail_results is not None
        )

    def _render_file_info(data, utils, app):
        file_info = data['file_info']
        
        if 'pe_info' in file_info:
            pe_info = file_info['pe_info']
            
            for section in pe_info['sections']:
                section['entropy_risk'] = utils.get_entropy_risk_level(section['entropy'])
                app.logger.debug(f"Calculated entropy risk for section {section.get('name', 'unknown')}: {section['entropy_risk']}")

            grouped_imports = {}
            for imp in pe_info.get('suspicious_imports', []):
                dll = imp['dll']
                if dll not in grouped_imports:
                    grouped_imports[dll] = []
                grouped_imports[dll].append(imp)
            pe_info['grouped_suspicious_imports'] = grouped_imports
            app.logger.debug(f"Grouped suspicious imports for {len(grouped_imports)} DLLs")

            if 'checksum_info' in pe_info:
                checksum = pe_info['checksum_info']
                checksum['stored_checksum'] = utils.format_hex(checksum['stored_checksum'])
                checksum['calculated_checksum'] = utils.format_hex(checksum['calculated_checksum'])
                app.logger.debug(f"Formatted checksum values - Stored: {checksum['stored_checksum']}, Calculated: {checksum['calculated_checksum']}")

        app.logger.debug("Rendering file_info.html template")
        return render_template(
            'file_info.html',
            file_info=file_info,
            entropy_risk_levels={'High': 7.2, 'Medium': 6.8, 'Low': 0}
        )

    def _render_analysis_info(data, analysis_type, route_helpers, app):
        results_key = f'{analysis_type}_results'
        analysis_results = data[results_key]
        
        if not analysis_results:
            app.logger.debug(f"No {analysis_type} analysis results found")
            return render_template('error.html', error=f'No {analysis_type} analysis results found'), 404

        app.logger.debug(f"Successfully loaded {analysis_type} analysis results")
        detections = route_helpers.get_detection_counts(data)
        
        if analysis_type == 'static':
            return _render_static_results(data, analysis_results, detections, app)
        else:
            return _render_dynamic_results(data, analysis_results, detections, app)

    def _render_static_results(data, analysis_results, detections, app):
        checkplz_detections = 0
        checkplz_findings = analysis_results.get('checkplz', {}).get('findings', {})
        if isinstance(checkplz_findings, dict):
            checkplz_detections = 1 if checkplz_findings.get('initial_threat') else 0
        app.logger.debug(f"Checkplz detections: {checkplz_detections}")
        
        formatted_duration = _format_scan_duration(analysis_results, app.logger)
        
        app.logger.debug("Rendering static_info.html template")
        return render_template(
            'static_info.html',
            file_info=data['file_info'],
            analysis_results=analysis_results,
            yara_detections=detections['yara'],
            checkplz_detections=checkplz_detections,
            stringnalyzer_results=analysis_results.get('stringnalyzer', {}),
            scan_duration=formatted_duration
        )

    def _render_dynamic_results(data, analysis_results, detections, app):
        app.logger.debug("Rendering dynamic_info.html template")
        return render_template(
            'dynamic_info.html',
            file_info=data['file_info'],
            analysis_results=analysis_results,
            yara_detections=detections['yara'],
            pesieve_detections=detections['pesieve'],
            moneta_detections=detections['moneta'],
            patriot_detections=detections['patriot'],
            hsb_detections=detections['hsb']
        )

    def _format_scan_duration(analysis_results, logger):
        try:
            raw_duration = analysis_results.get('analysis_metadata', {}).get('total_duration', {})
            logger.debug(f"Raw scan duration value: {raw_duration}")
            scan_duration = float(raw_duration or 0)
            
            minutes = int(scan_duration // 60)
            seconds = int(scan_duration % 60)
            milliseconds = int((scan_duration % 1) * 1000)
            formatted_duration = f"{minutes:02d}:{seconds:02d}.{milliseconds:03d}"
            logger.debug(f"Formatted scan duration: {formatted_duration}")
            return formatted_duration
        except (TypeError, ValueError, AttributeError) as e:
            logger.error(f"Error formatting scan duration: {e}")
            return "00:00.000"

    @app.route('/summary', methods=['GET'])
    def summary_page():
        return render_template('summary.html')

    @app.route('/files', methods=['GET'])
    @error_handler
    def get_files_summary():
        app.logger.debug("Starting to generate files and PID-based analysis summaries.")
        
        results_dir = app.config['utils']['result_folder']
        file_based_summary = {}
        pid_based_summary = {}
        
        try:
            all_items = os.listdir(results_dir)
            app.logger.debug(f"Found {len(all_items)} items in results directory: {results_dir}")
        except Exception as e:
            app.logger.error(f"Error accessing results directory '{results_dir}': {e}")
            raise

        for item in all_items:
            item_path = os.path.join(results_dir, item)
            if not os.path.isdir(item_path):
                app.logger.debug(f"Skipping non-directory item: {item}")
                continue

            if item.startswith('dynamic_'):
                _process_pid_summary(item, item_path, pid_based_summary, utils, app.logger)
            else:
                _process_file_summary(item, item_path, file_based_summary, utils, app.logger)

        # Separate drivers from payloads
        driver_based_summary = {}
        payload_based_summary = {}
        
        for key, file_data in file_based_summary.items():
            filename = file_data.get('filename', '')
            if filename.lower().endswith('.sys'):
                driver_based_summary[key] = file_data
            else:
                payload_based_summary[key] = file_data


        # Debug each driver in detail
        for driver_key, driver_data in driver_based_summary.items():

            
            # Focus on risk assessment data
            risk_assessment = driver_data.get('risk_assessment', {})
            # Show all keys in driver data
            app.logger.debug(f"All driver data keys: {list(driver_data.keys())}")
            
            # Show full driver data structure (be careful - this might be large)
            app.logger.debug(f"Full driver data: {driver_data}")
        


        return jsonify({
            'status': 'success',
            'driver_based': {'count': len(driver_based_summary), 'drivers': driver_based_summary},
            'payload_based': {'count': len(payload_based_summary), 'payloads': payload_based_summary},
            'pid_based': {'count': len(pid_based_summary), 'processes': pid_based_summary}
        })

    def _process_pid_summary(item, item_path, pid_based_summary, utils, logger):
        pid = item.replace('dynamic_', '')
        logger.debug(f"Processing dynamic analysis results for PID: {pid}")

        dynamic_results_path = os.path.join(item_path, 'dynamic_analysis_results.json')
        if not os.path.exists(dynamic_results_path):
            return

        try:
            dynamic_results = utils.load_json_file(dynamic_results_path)
            if not dynamic_results:
                return
            logger.debug(f"Loaded dynamic analysis results for PID: {pid}")

            process_info = dynamic_results.get('moneta', {}).get('findings', {}).get('process_info', {})
            risk_score, risk_factors = utils.calculate_risk(analysis_type='process', dynamic_results=dynamic_results)
            risk_level = utils.get_risk_level(risk_score)

            yara_matches = dynamic_results.get('yara', {}).get('matches', [])
            pe_sieve_findings = dynamic_results.get('pe_sieve', {}).get('findings', {})
            moneta_findings = dynamic_results.get('moneta', {}).get('findings', {})
            hsb_detections = dynamic_results.get('hsb', {}).get('findings', {}).get('detections', [])

            pid_based_summary[pid] = {
                'pid': pid,
                'process_name': process_info.get('name', 'unknown'),
                'process_path': process_info.get('path', 'unknown'),
                'architecture': process_info.get('arch', 'unknown'),
                'analysis_time': dynamic_results.get('analysis_time', 'unknown'),
                'result_dir_full_path': os.path.abspath(item_path),
                'risk_assessment': {
                    'score': risk_score,
                    'level': risk_level,
                    'factors': risk_factors
                },
                'analysis_summary': {
                    'yara': {
                        'total_findings': len(yara_matches),
                        'findings': yara_matches
                    },
                    'pe_sieve': {
                        'total_findings': pe_sieve_findings.get('total_suspicious', 0),
                        'findings': pe_sieve_findings
                    },
                    'moneta': {
                        'total_findings': sum(1 for key, value in moneta_findings.items() 
                                            if key.startswith('total_') and isinstance(value, (int, float)) and value > 0),
                        'findings': moneta_findings
                    },
                    'hsb': {
                        'total_findings': sum(len(det.get('findings', [])) for det in hsb_detections if det.get('pid') == int(pid)),
                        'findings': [det for det in hsb_detections if det.get('pid') == int(pid)]
                    }
                }
            }
            logger.debug(f"Processed dynamic analysis for PID: {pid}")
        except Exception as e:
            logger.error(f"Error processing PID {pid}: {e}")

    def _process_file_summary(item, item_path, file_based_summary, utils, logger):
        file_info_path = os.path.join(item_path, 'file_info.json')
        if not os.path.exists(file_info_path):
            logger.debug(f"No file_info.json found in {item_path}. Skipping.")
            return

        try:
            file_info = utils.load_json_file(file_info_path)
            if not file_info:
                return
            logger.debug(f"Loaded file info for item: {item}")

            filename = file_info.get('original_name', 'unknown')
            is_driver = filename.lower().endswith('.sys')
            
            # Check for appropriate analysis files based on file type
            if is_driver:
                # Driver analysis uses byovd_results.json
                byovd_path = os.path.join(item_path, 'byovd_results.json')
                has_static_analysis = os.path.exists(byovd_path)
                has_dynamic_analysis = False  # Drivers don't have dynamic analysis
                
                # Load BYOVD results for risk calculation
                byovd_results = None
                if has_static_analysis:
                    byovd_results = utils.load_json_file(byovd_path)
                    logger.debug(f"Loaded BYOVD analysis results for driver: {item}")
                    
                risk_score, risk_factors = utils.calculate_risk(
                    analysis_type='driver',  # You'll need to handle this in utils.calculate_risk
                    file_info=file_info,
                    byovd_results=byovd_results
                )
            else:
                # Standard payload analysis
                static_path = os.path.join(item_path, 'static_analysis_results.json')
                dynamic_path = os.path.join(item_path, 'dynamic_analysis_results.json')

                static_results = None
                if os.path.exists(static_path):
                    static_results = utils.load_json_file(static_path)
                    logger.debug(f"Loaded static analysis results for item: {item}")

                dynamic_results = None
                if os.path.exists(dynamic_path):
                    dynamic_results = utils.load_json_file(dynamic_path)
                    logger.debug(f"Loaded dynamic analysis results for item: {item}")

                has_static_analysis = os.path.exists(static_path)
                has_dynamic_analysis = os.path.exists(dynamic_path)
                
                risk_score, risk_factors = utils.calculate_risk(
                    analysis_type='file',
                    file_info=file_info,
                    static_results=static_results,
                    dynamic_results=dynamic_results
                )

            risk_level = utils.get_risk_level(risk_score)
            
            file_based_summary[item] = {
                'md5': file_info.get('md5', 'unknown'),
                'sha256': file_info.get('sha256', 'unknown'),
                'filename': filename,
                'file_size': file_info.get('size', 0),
                'upload_time': file_info.get('upload_time', 'unknown'),
                'result_dir_full_path': os.path.abspath(item_path),
                'entropy_value': file_info.get('entropy_analysis', {}).get('value', 0),
                'detection_risk': file_info.get('entropy_analysis', {}).get('detection_risk', 'Unknown'),
                'has_static_analysis': has_static_analysis,
                'has_dynamic_analysis': has_dynamic_analysis,
                'risk_assessment': {
                    'score': risk_score,
                    'level': risk_level,
                    'factors': risk_factors
                }
            }
            logger.debug(f"Processed file-based analysis for item: {item}")
        except Exception as e:
            logger.error(f"Error processing file item {item}: {e}")

    @app.route('/doppelganger', methods=['GET', 'POST'])
    @error_handler
    def doppelganger():
        app.logger.debug("Accessed doppelganger endpoint")

        analysis_type = 'blender'
        if request.method == 'GET':
            analysis_type = request.args.get('type', 'blender')
        else:
            if request.is_json:
                analysis_type = request.json.get('type', 'blender')
            else:
                analysis_type = request.form.get('type', 'blender')

        if analysis_type not in ['blender', 'fuzzy']:
            analysis_type = 'blender'

        analyzer = BlenderAnalyzer(app.config, logger=app.logger) if analysis_type == 'blender' else FuzzyHashAnalyzer(app.config, logger=app.logger)

        if request.method == 'GET':
            payload_hash = request.args.get('hash')
            if payload_hash:
                return _handle_doppelganger_hash_request(analyzer, analysis_type, payload_hash, app)

            if analysis_type == 'blender':
                return _handle_blender_initial_load(app)
            else:
                return _handle_fuzzy_initial_load(analyzer)

        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 415

        data = request.json
        operation = data.get('operation')
        
        if not operation:
            app.logger.error("Missing operation in request")
            return jsonify({'error': 'Operation type is required'}), 400

        app.logger.debug(f"POST request received. Operation: {operation}")

        if analysis_type == 'blender':
            return _handle_blender_operations(analyzer, operation, data, app)
        else:
            return _handle_fuzzy_operations(analyzer, operation, data, app)

    def _handle_doppelganger_hash_request(analyzer, analysis_type, payload_hash, app):
        if analysis_type == 'blender':
            comparison_result = analyzer.compare_payload(payload_hash)
            
            if isinstance(comparison_result, dict) and comparison_result.get("status") == "error":
                return jsonify({'error': comparison_result.get("message", "Unknown error")}), 400

            return jsonify({
                'status': 'success',
                'message': 'Comparison completed',
                'result': comparison_result
            })
        else:
            file_path = _find_file_by_hash_for_fuzzy(analyzer, payload_hash, app)
            if not file_path:
                return jsonify({'error': 'File not found'}), 404
            
            results = analyzer.analyze_files([file_path], threshold=1)
            return jsonify({
                'status': 'success',
                'message': 'Analysis completed successfully',
                'results': results
            })

    def _find_file_by_hash_for_fuzzy(analyzer, payload_hash, app):
        upload_folder = os.path.abspath(app.config['utils']['upload_folder'])
        
        if hasattr(app, 'file_cache'):
            file_path = app.file_cache.get_file_by_hash(payload_hash)
            if file_path:
                return file_path
        
        try:
            for filename in os.listdir(upload_folder):
                full_path = os.path.join(upload_folder, filename)
                if os.path.isfile(full_path):
                    file_hash = analyzer._compute_md5(full_path)
                    if file_hash == payload_hash:
                        if hasattr(app, 'file_cache'):
                            app.file_cache.add_file(full_path, file_hash)
                        return full_path
        except FileNotFoundError:
            app.logger.error(f"Upload folder not found: {upload_folder}")
        
        return None

    def _handle_blender_initial_load(app):
        result_folder = os.path.join(
            app.config['analysis']['doppelganger']['db']['path'],
            app.config['analysis']['doppelganger']['db']['blender']
        )
        latest_report = None
        last_modified = None

        if os.path.exists(result_folder):
            files = [f for f in os.listdir(result_folder) if f.startswith("BlenderScan_")]
            if files:
                latest_file = max(files, key=lambda x: os.path.getmtime(os.path.join(result_folder, x)))
                file_path = os.path.join(result_folder, latest_file)
                with open(file_path, 'r') as f:
                    latest_report = f.read()
                last_modified = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')

        return render_template('doppelganger.html', 
                             analysis_type='blender',
                             initial_data=latest_report,
                             last_modified=last_modified)

    def _handle_fuzzy_initial_load(analyzer):
        db_stats = analyzer.get_db_stats()
        return render_template('doppelganger.html',
                             analysis_type='fuzzy',
                             db_stats=db_stats)

    def _handle_blender_operations(analyzer, operation, data, app):
        if operation == 'scan':
            parsed_processes = analyzer.take_system_sample()
            return jsonify({
                'status': 'success',
                'message': 'System scan completed',
                'processes': parsed_processes
            })
        else:
            return jsonify({'error': 'Invalid operation for blender analysis'}), 400

    def _handle_fuzzy_operations(analyzer, operation, data, app):
        if operation == 'create_db':
            if 'folder_path' not in data:
                return jsonify({'error': 'Folder path is required'}), 400
                
            folder_path = data['folder_path']
            extensions = data.get('extensions', None)
            
            if extensions and isinstance(extensions, str):
                extensions = [ext.strip() for ext in extensions.split(',')]
            
            stats = analyzer.create_db_from_folder(folder_path, extensions)
            return jsonify({
                'status': 'success',
                'message': 'Database created successfully',
                'stats': stats
            })
        elif operation == 'analyze':
            if 'hash' not in data:
                return jsonify({'error': 'File hash is required'}), 400
                
            file_hash = data['hash']
            file_path = _find_file_by_hash_for_fuzzy(analyzer, file_hash, app)
            
            if not file_path:
                return jsonify({'error': 'File not found'}), 404
                
            threshold = data.get('threshold', 1)
            results = analyzer.analyze_files([file_path], threshold)
            
            return jsonify({
                'status': 'success',
                'message': 'Analysis completed successfully',
                'results': results
            })
        else:
            return jsonify({'error': 'Invalid operation for fuzzy analysis'}), 400


    # Add this route in the register_routes function in routes.py

    @app.route('/holygrail', methods=['GET', 'POST'])
    @error_handler
    def holygrail():
        """
        holygrail endpoint for kernel driver analysis
        GET: Render upload page or handle analysis request
        POST: Handle file upload for kernel drivers
        """
        app.logger.debug("Accessed holygrail endpoint")
        
        if request.method == 'GET':
            # Check if this is an analysis request
            target_hash = request.args.get('hash')
            
            if target_hash:
                app.logger.debug(f"Starting BYOVD analysis for hash: {target_hash}")
                
                try:
                    # Find the uploaded file
                    file_path = utils.find_file_by_hash(target_hash, app.config['utils']['upload_folder'])
                    if not file_path:
                        app.logger.error(f"Driver file not found for hash: {target_hash}")
                        return jsonify({
                            'status': 'error',
                            'error': 'Driver file not found'
                        }), 404
                    
                    app.logger.debug(f"Found driver file: {file_path}")
                    
                    # Find result path for saving analysis results
                    result_path = utils.find_file_by_hash(target_hash, app.config['utils']['result_folder'])
                    if not result_path:
                        app.logger.error(f"Result path not found for hash: {target_hash}")
                        return jsonify({
                            'status': 'error',
                            'error': 'Result path not found'
                        }), 404
                    
                    app.logger.debug(f"Results will be saved to: {result_path}")
                    
                    # Run analysis
                    analyzer = HolyGrailAnalyzer(app.config, logger=app.logger)
                    results = analyzer.analyze(file_path)
                    
                    app.logger.debug(f"Analysis completed with status: {results.get('status')}")
                    
                    if results['status'] == 'completed':
                        # pull compile_time directly from the file, not from file_info
                        compile_time = None
                        try:
                            pe = utils.get_pe_info(file_path)
                            pe_info = (pe or {}).get('pe_info') or {}
                            compile_time = pe_info.get('compile_time')
                        except Exception as e:
                            app.logger.debug(f"Compile time extraction failed: {e}")
                        
                        # Add compile_time to results before saving
                        if compile_time:
                            results['compile_time'] = compile_time
                            # Also add it to detailed_analysis if it exists
                            if 'findings' in results and 'detailed_analysis' in results['findings']:
                                results['findings']['detailed_analysis']['compile_time'] = compile_time
                        
                        # Save results to results folder like other analysis types
                        route_helpers.save_analysis_results(results, result_path, 'byovd_results.json')
                        app.logger.debug(f"HolyGrail results saved to: {result_path}/byovd_results.json")
                        
                        full_payload = {
                            'status': 'success',
                            'message': 'BYOVD analysis completed',
                            'results': results,
                            'compile_time': compile_time,
                        }
                        return jsonify(full_payload)

                    elif results['status'] == 'disabled':
                        return jsonify({
                            'status': 'error',
                            'message': 'holygrail analyzer is disabled in configuration',
                            'error': results.get('error')
                        }), 503
                    else:
                        app.logger.error(f"Analysis failed: {results.get('error')}")
                        return jsonify({
                            'status': 'error',
                            'message': results.get('error', 'Analysis failed')
                        }), 500
                        
                except Exception as e:
                    app.logger.error(f"Exception during BYOVD analysis: {str(e)}", exc_info=True)
                    return jsonify({
                        'status': 'error',
                        'message': f'Unexpected error: {str(e)}'
                    }), 500
            
            # Regular page load
            app.logger.debug("Rendering holygrail upload page")
            return render_template('holygrail.html')
        
        # Handle file upload
        if 'file' not in request.files:
            app.logger.debug("No file part in holygrail request")
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            app.logger.debug("No file selected in holygrail upload")
            return jsonify({'error': 'No selected file'}), 400
        
        # Validate file is a driver
        if not _is_kernel_driver_file(file.filename):
            app.logger.debug(f"File '{file.filename}' is not a valid kernel driver format")
            return jsonify({'error': 'File must be a kernel driver (.sys)'}), 400
        
        app.logger.debug(f"Kernel driver file '{file.filename}' uploaded. Saving...")
        file_info = utils.save_uploaded_file(file)
        
        app.logger.debug(f"Kernel driver '{file.filename}' saved successfully")
        return jsonify({
            'message': 'Kernel driver uploaded successfully',
            'file_info': file_info,
            'next_step': 'Ready for BYOVD analysis'
        }), 200
    
    def _is_kernel_driver_file(filename):
        """Check if file is a potential kernel driver"""
        if not filename:
            return False
        
        driver_extensions = ['.sys']
        return any(filename.lower().endswith(ext) for ext in driver_extensions)

    @app.route('/cleanup', methods=['POST'])
    @error_handler
    def cleanup():
        app.logger.debug("Starting cleanup process.")
        
        folders_to_clean = {
            'uploads': app.config['utils']['upload_folder'],
            'results': app.config['utils']['result_folder']
        }
        
        results = route_helpers.process_file_cleanup(folders_to_clean)
        
        # Clean doppelganger folders
        doppelganger_base = app.config['analysis']['doppelganger']['db']['path']
        doppelganger_folders = [app.config['analysis']['doppelganger']['db']['blender']]
        
        for folder_name in doppelganger_folders:
            folder_path = os.path.join(doppelganger_base, folder_name)
            if os.path.exists(folder_path):
                app.logger.debug(f"Cleaning doppelganger folder contents: {folder_path}")
                try:
                    files = os.listdir(folder_path)
                    for f in files:
                        file_path = os.path.join(folder_path, f)
                        if os.path.isfile(file_path):
                            os.unlink(file_path)
                            results['result_cleaned'] += 1
                            app.logger.debug(f"Deleted file: {file_path}")
                except Exception as e:
                    app.logger.error(f"Error accessing folder {folder_path}: {e}")
                    results['errors'].append(f"Error accessing {folder_name}: {str(e)}")
        
        # Clean PE-Sieve analysis folders
        analysis_path = os.path.join('.', 'Scanners', 'PE-Sieve', 'Analysis')
        if os.path.exists(analysis_path):
            try:
                results['analysis_cleaned'] += route_helpers._clean_process_folders(analysis_path)
            except Exception as e:
                app.logger.error(f"Error accessing analysis folder: {e}")
                results['errors'].append(f"Error accessing analysis folder: {str(e)}")
        
        # Clean HolyGrail analysis results
        holygrail_config = app.config.get('analysis', {}).get('holygrail', {})
        if holygrail_config.get('enabled', False):
            holygrail_results_path = holygrail_config.get('results_path')
            if holygrail_results_path and os.path.exists(holygrail_results_path):
                app.logger.debug(f"Cleaning HolyGrail results folder: {holygrail_results_path}")
                try:
                    files = os.listdir(holygrail_results_path)
                    for f in files:
                        file_path = os.path.join(holygrail_results_path, f)
                        if os.path.isfile(file_path):
                            os.unlink(file_path)
                            results['analysis_cleaned'] += 1
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                            results['analysis_cleaned'] += 1
                            app.logger.debug(f"Deleted HolyGrail result folder: {file_path}")
                except Exception as e:
                    app.logger.error(f"Error cleaning HolyGrail results folder {holygrail_results_path}: {e}")
                    results['errors'].append(f"Error cleaning HolyGrail results: {str(e)}")
        
        status = 'warning' if results['errors'] else 'success'
        message = 'Cleanup completed with some errors' if results['errors'] else 'Cleanup completed successfully'
        app.logger.debug(f"Cleanup completed. Status: {status}, Message: {message}")

        return jsonify({
            'status': status,
            'message': message,
            'details': results
        }), 200 if status == 'success' else 207

    @app.route('/health', methods=['GET'])
    @error_handler
    def health_check():
        app.logger.debug("Starting health check.")
        config = app.config
        upload_config = config.get('utils', {})
        analysis_config = config.get('analysis', {})
        issues = []

        upload_folder = upload_config.get('upload_folder')
        if not upload_folder:
            app.logger.warning("Upload folder path is not configured.")
            issues.append("Upload folder path is not configured.")
        elif not os.path.isdir(upload_folder):
            app.logger.warning(f"Upload folder does not exist: {upload_folder}")
            issues.append(f"Upload folder does not exist: {upload_folder}")

        static_section = analysis_config.get('static', {})
        dynamic_section = analysis_config.get('dynamic', {})
        holygrail_section = analysis_config.get('holygrail', {})

        # Check static analysis tools
        for tool_name in static_section.keys():
            _check_analysis_tool(static_section, tool_name, issues, app.logger)

        # Check dynamic analysis tools
        for tool_name in dynamic_section.keys():
            _check_analysis_tool(dynamic_section, tool_name, issues, app.logger)
        
        # Check HolyGrail tool
        _check_holygrail_tool(holygrail_section, issues, app.logger)

        static_tools = {tool: static_section.get(tool, {}).get('enabled', False) for tool in static_section.keys()}
        dynamic_tools = {tool: dynamic_section.get(tool, {}).get('enabled', False) for tool in dynamic_section.keys()}
        holygrail_status = holygrail_section.get('enabled', False)

        status = 'ok' if not issues else 'degraded'
        app.logger.debug(f"Health check completed. Status: {status}")
        
        return jsonify({
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'upload_folder_accessible': os.path.isdir(upload_folder) if upload_folder else False,
            'issues': issues,
            'configuration': {
                'static_analysis': static_tools,
                'dynamic_analysis': dynamic_tools,
                'holygrail_analysis': holygrail_status
            }
        }), 200 if status == 'ok' else 503

    def _check_holygrail_tool(holygrail_config, issues, logger):
        """Check HolyGrail tool configuration and availability"""
        if holygrail_config.get('enabled', False):
            logger.debug("Checking HolyGrail tool configuration")
            
            # Check tool path
            tool_path = holygrail_config.get('tool_path')
            if not tool_path:
                issues.append("HolyGrail: tool path not configured")
            elif not os.path.isfile(tool_path):
                issues.append(f"HolyGrail: tool not found at {tool_path}")
            
            # Check policies path
            policies_path = holygrail_config.get('policies_path')
            if not policies_path:
                issues.append("HolyGrail: policies path not configured")
            elif not os.path.isdir(policies_path):
                issues.append(f"HolyGrail: policies directory not found at {policies_path}")
            
            # Check results path (create if doesn't exist)
            results_path = holygrail_config.get('results_path')
            if not results_path:
                issues.append("HolyGrail: results path not configured")
            elif not os.path.exists(results_path):
                try:
                    os.makedirs(results_path, exist_ok=True)
                    logger.debug(f"Created HolyGrail results directory: {results_path}")
                except Exception as e:
                    issues.append(f"HolyGrail: unable to create results directory {results_path}: {str(e)}")
            
            # Check timeout configuration
            timeout = holygrail_config.get('timeout')
            if timeout is None:
                issues.append("HolyGrail: timeout not configured")
            elif not isinstance(timeout, (int, float)) or timeout <= 0:
                issues.append("HolyGrail: invalid timeout value")

    def _check_analysis_tool(section, tool_name, issues, logger):
        tool_config = section.get(tool_name, {})
        if tool_config.get('enabled', False):
            logger.debug(f"Checking tool configuration: {tool_name}")
            tool_path = tool_config.get('tool_path')
            if not tool_path:
                issues.append(f"{tool_name}: tool path not configured")
            elif not os.path.isfile(tool_path):
                issues.append(f"{tool_name}: tool not found at {tool_path}")
            
            rules_path = tool_config.get('rules_path')
            if rules_path and not os.path.isfile(rules_path):
                issues.append(f"{tool_name}: rules not found at {rules_path}")

    @app.route('/file/<target>', methods=['DELETE'])
    @error_handler
    def delete_file(target):
        app.logger.debug(f"Deleting file: {target}")
        upload_path = utils.find_file_by_hash(target, app.config['utils']['upload_folder'])
        result_path = utils.find_file_by_hash(target, app.config['utils']['result_folder'])
        analysis_path = os.path.join('.', 'Scanners', 'PE-Sieve', 'Analysis')

        deleted = {'upload': False, 'result': False, 'analysis': False}

        if upload_path:
            try:
                os.unlink(upload_path)
                deleted['upload'] = True
                app.logger.debug(f"Deleted upload file: {upload_path}")
            except Exception as e:
                app.logger.error(f"Error deleting upload file {upload_path}: {e}")

        if result_path:
            try:
                shutil.rmtree(result_path)
                deleted['result'] = True
                app.logger.debug(f"Deleted result folder: {result_path}")
            except Exception as e:
                app.logger.error(f"Error deleting result folder {result_path}: {e}")

        process_folders = glob.glob(os.path.join(analysis_path, f'*_{target}_*'))
        for folder in process_folders:
            try:
                shutil.rmtree(folder)
                deleted['analysis'] = True
                app.logger.debug(f"Deleted analysis folder: {folder}")
            except Exception as e:
                app.logger.error(f"Error deleting analysis folder {folder}: {e}")

        if not any(deleted.values()):
            app.logger.warning(f"File not found: {target}")
            return jsonify({'status': 'error', 'message': 'File not found'}), 404

        app.logger.debug(f"File {target} deleted successfully.")
        return jsonify({'status': 'success', 'message': 'File deleted successfully', 'details': deleted})

    @app.route('/api/results/<target>/static', methods=['GET'])
    @error_handler
    def api_static_results(target):
        app.logger.debug(f"Fetching static analysis results for target: {target}")
        result_path = utils.find_file_by_hash(target, app.config['utils']['result_folder'])
        if not result_path:
            app.logger.warning(f"Static results not found for target: {target}")
            return jsonify({'error': 'Results not found'}), 404

        static_path = os.path.join(result_path, 'static_analysis_results.json')
        if not os.path.exists(static_path):
            app.logger.warning(f"Static analysis results not found for target: {target}")
            return jsonify({'error': 'Static analysis results not found'}), 404

        with open(static_path, 'r') as f:
            app.logger.debug(f"Returning static analysis results for target: {target}")
            return jsonify(json.load(f))

    @app.route('/api/results/<target>/dynamic', methods=['GET'])
    @error_handler
    def api_dynamic_results(target):
        app.logger.debug(f"Fetching dynamic analysis results for target: {target}")

        if target.isdigit():
            result_folder = os.path.join(app.config['utils']['result_folder'], f'dynamic_{target}')
            dynamic_path = os.path.join(result_folder, 'dynamic_analysis_results.json')
        else:
            result_path = utils.find_file_by_hash(target, app.config['utils']['result_folder'])
            if not result_path:
                app.logger.warning(f"Dynamic results not found for target: {target}")
                return jsonify({'error': 'Results not found'}), 404
            dynamic_path = os.path.join(result_path, 'dynamic_analysis_results.json')

        if not os.path.exists(dynamic_path):
            app.logger.warning(f"Dynamic analysis results not found for target: {target}")
            return jsonify({'error': 'Dynamic analysis results not found'}), 404

        with open(dynamic_path, 'r') as f:
            app.logger.debug(f"Returning dynamic analysis results for target: {target}")
            return jsonify(json.load(f))

    @app.route('/api/results/<target>/info', methods=['GET'])
    @error_handler
    def api_file_info(target):
        app.logger.debug(f"Fetching file info for target: {target}")
        result_path = utils.find_file_by_hash(target, app.config['utils']['result_folder'])
        if not result_path:
            app.logger.warning(f"File info not found for target: {target}")
            return jsonify({'error': 'File info not found'}), 404

        file_info_path = os.path.join(result_path, 'file_info.json')
        if not os.path.exists(file_info_path):
            app.logger.warning(f"File info not found for target: {target}")
            return jsonify({'error': 'File info not found'}), 404

        with open(file_info_path, 'r') as f:
            app.logger.debug(f"Returning file info for target: {target}")
            return jsonify(json.load(f))

    @app.route('/api/results/<target>/holygrail', methods=['GET'])
    @error_handler
    def api_byovd_info(target):
        app.logger.debug(f"Fetching file info for target: {target}")
        result_path = utils.find_file_by_hash(target, app.config['utils']['result_folder'])
        if not result_path:
            app.logger.warning(f"File info not found for target: {target}")
            return jsonify({'error': 'File info not found'}), 404

        file_info_path = os.path.join(result_path, 'byovd_results.json')
        if not os.path.exists(file_info_path):
            app.logger.warning(f"File info not found for target: {target}")
            return jsonify({'error': 'File info not found'}), 404

        with open(file_info_path, 'r') as f:
            app.logger.debug(f"Returning file info for target: {target}")
            return jsonify(json.load(f))
        
        
    @app.route('/api/report/<target>', methods=['GET'])
    @error_handler
    def generate_report(target):
        app.logger.debug(f"Generating report for target: {target}")
        
        data, error_msg, is_error = route_helpers.load_analysis_data(target)
        if is_error:
            app.logger.warning(f"Error loading data for report generation: {error_msg}")
            return jsonify({'error': error_msg}), 404
        
        html_report = utils.generate_html_report(
            file_info=data['file_info'],
            static_results=data['static_results'],
            dynamic_results=data['dynamic_results'],
            pid=data['pid']
        )
        
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        if data['is_pid']:
            process_info = data['dynamic_results'].get('moneta', {}).get('findings', {}).get('process_info', {})
            process_name = process_info.get('name', f"PID_{data['pid']}")
            filename = f"Report_{process_name}_{data['pid']}_{timestamp}.html"
        else:
            original_name = data['file_info'].get('original_name', 'unknown')
            file_hash = data['file_info'].get('md5', target)
            filename = f"Report_{original_name}_{file_hash[:8]}_{timestamp}.html"
        
        download = request.args.get('download', 'false').lower() == 'true'
        if download:
            response = Response(html_report, mimetype='text/html')
            response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
            app.logger.debug(f"Returning downloadable report: {filename}")
            return response
        else:
            app.logger.debug("Returning HTML report for display")
            return html_report

    @app.route('/report/<target>', methods=['GET'])
    @error_handler
    def report_page(target):
        app.logger.debug(f"Redirecting to download report for target: {target}")
        
        data, error_msg, is_error = route_helpers.load_analysis_data(target)
        if is_error:
            app.logger.warning(f"Error loading data for report page: {error_msg}")
            return render_template('error.html', error=error_msg), 404
        
        return redirect(f'/api/report/{target}?download=true')

    @app.errorhandler(404)
    def page_not_found(error):
        app.logger.debug(f"Page not found: {request.path}")
        return render_template('error.html', error=f"Page not found: {request.path}"), 404

    return app