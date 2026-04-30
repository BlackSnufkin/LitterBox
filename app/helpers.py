# app/helpers.py
"""Shared route-level helpers used across blueprints."""
import glob
import json
import os
import shutil

from .utils import json_helpers, path_manager, risk_analyzer, validators


class RouteHelpers:
    """Loads analysis data, computes risk, saves results, and runs cleanup."""

    def __init__(self, app_config, logger):
        self.config = app_config
        self.logger = logger

    def load_analysis_data(self, target):
        """Unified loader for both file-hash and PID targets."""
        if target.isdigit():
            return self._load_pid_data(target)
        return self._load_file_data(target)

    def _load_pid_data(self, pid):
        is_valid, error_msg = validators.validate_pid(pid)
        if not is_valid:
            return None, error_msg, True

        result_folder = os.path.join(self.config['utils']['result_folder'], f'dynamic_{pid}')
        if not os.path.exists(result_folder):
            return None, f'Process with PID {pid} does not exist', True

        dynamic_path = os.path.join(result_folder, 'dynamic_analysis_results.json')
        if not os.path.exists(dynamic_path):
            return None, f'Dynamic analysis results for PID {pid} not found', True

        dynamic_results = json_helpers.load_json_file(dynamic_path)
        if not dynamic_results:
            return None, 'Error loading dynamic analysis results', True

        return {
            'is_pid': True,
            'pid': pid,
            'result_path': result_folder,
            'file_info': None,
            'static_results': None,
            'dynamic_results': dynamic_results,
            'byovd_results': None,
            'edr_results': None,
        }, None, False

    def _load_file_data(self, file_hash):
        result_path = path_manager.find_file_by_hash(file_hash, self.config['utils']['result_folder'])
        if not result_path:
            return None, 'Results not found', True

        file_info_path = os.path.join(result_path, 'file_info.json')
        if not os.path.exists(file_info_path):
            return None, 'File info not found', True

        file_info = json_helpers.load_json_file(file_info_path)
        if not file_info:
            return None, 'Error loading file info', True

        static_path = os.path.join(result_path, 'static_analysis_results.json')
        dynamic_path = os.path.join(result_path, 'dynamic_analysis_results.json')
        byovd_path = os.path.join(result_path, 'byovd_results.json')

        static_results = json_helpers.load_json_file(static_path) if os.path.exists(static_path) else None
        dynamic_results = json_helpers.load_json_file(dynamic_path) if os.path.exists(dynamic_path) else None
        byovd_results = json_helpers.load_json_file(byovd_path) if os.path.exists(byovd_path) else None

        # Discover all per-profile EDR result files (edr_<profile>_results.json).
        # A file may have been run against multiple profiles — load them all.
        edr_results = {}
        prefix, suffix = 'edr_', '_results.json'
        for entry in os.listdir(result_path):
            if entry.startswith(prefix) and entry.endswith(suffix):
                profile_name = entry[len(prefix):-len(suffix)]
                loaded = json_helpers.load_json_file(os.path.join(result_path, entry))
                if loaded:
                    edr_results[profile_name] = loaded

        return {
            'is_pid': False,
            'pid': None,
            'result_path': result_path,
            'file_info': file_info,
            'static_results': static_results,
            'dynamic_results': dynamic_results,
            'byovd_results': byovd_results,
            'edr_results': edr_results or None,
        }, None, False

    def calculate_and_add_risk(self, data):
        if data['is_pid']:
            risk_score, risk_factors = risk_analyzer.calculate_risk(
                analysis_type='process',
                dynamic_results=data['dynamic_results'],
            )
        else:
            # Note: EDR results are intentionally NOT folded in here. The
            # file_info / results page has tabs only for Static and Dynamic;
            # EDR is its own analysis type at /analyze/edr/<profile>/<hash>
            # with its own page, alerts, and Detection-Score contribution.
            # Keeping the file's score scoped to static+dynamic+PE keeps
            # the abstraction clean.
            risk_score, risk_factors = risk_analyzer.calculate_risk(
                analysis_type='file',
                file_info=data['file_info'],
                static_results=data['static_results'],
                dynamic_results=data['dynamic_results'],
            )

        risk_level = risk_analyzer.get_risk_level(risk_score)

        risk_data = {
            'score': risk_score,
            'level': risk_level,
            'factors': risk_factors,
        }

        if data['is_pid'] and data['dynamic_results']:
            data['dynamic_results']['risk_assessment'] = risk_data
        elif data['file_info']:
            data['file_info']['risk_assessment'] = risk_data

        return risk_score, risk_level, risk_factors

    def get_detection_counts(self, data):
        results = data['dynamic_results'] or data['static_results'] or {}
        return json_helpers.extract_detection_counts(results)

    def save_analysis_results(self, results, result_path, results_filename):
        results_file_path = os.path.join(result_path, results_filename)
        with open(results_file_path, 'w') as f:
            json.dump(results, f)
        self.logger.debug(f"Analysis results saved to: {results_file_path}")
        return results_file_path

    def process_file_cleanup(self, folders_to_clean):
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
        count = 0
        for f in os.listdir(folder_path):
            file_path = os.path.join(folder_path, f)
            if os.path.isfile(file_path):
                os.unlink(file_path)
                count += 1
        return count

    def _clean_folders_in_folder(self, folder_path):
        count = 0
        for f in os.listdir(folder_path):
            full_path = os.path.join(folder_path, f)
            if os.path.isdir(full_path):
                shutil.rmtree(full_path)
                count += 1
        return count

    def _clean_process_folders(self, analysis_path):
        count = 0
        for folder in glob.glob(os.path.join(analysis_path, 'process_*')):
            shutil.rmtree(folder)
            count += 1
        return count
