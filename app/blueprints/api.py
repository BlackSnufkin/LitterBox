# app/blueprints/api.py
"""JSON API endpoints + HTML report generation."""
import json
import os
from datetime import datetime

from flask import Blueprint, Response, current_app, jsonify, redirect, render_template, request

from ..services.error_handling import error_handler
from ..utils import path_manager, reporting

api_bp = Blueprint('api', __name__)


def _deps():
    return current_app.extensions['litterbox']


@api_bp.route('/api/results/<target>/static', methods=['GET'])
@error_handler
def api_static_results(target):
    app = current_app
    app.logger.debug(f"Fetching static analysis results for target: {target}")
    result_path = path_manager.find_file_by_hash(target, app.config['utils']['result_folder'])
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


@api_bp.route('/api/results/<target>/dynamic', methods=['GET'])
@error_handler
def api_dynamic_results(target):
    app = current_app
    app.logger.debug(f"Fetching dynamic analysis results for target: {target}")

    if target.isdigit():
        result_folder = os.path.join(app.config['utils']['result_folder'], f'dynamic_{target}')
        dynamic_path = os.path.join(result_folder, 'dynamic_analysis_results.json')
    else:
        result_path = path_manager.find_file_by_hash(target, app.config['utils']['result_folder'])
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


@api_bp.route('/api/results/<target>/info', methods=['GET'])
@error_handler
def api_file_info(target):
    app = current_app
    app.logger.debug(f"Fetching file info for target: {target}")
    result_path = path_manager.find_file_by_hash(target, app.config['utils']['result_folder'])
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


@api_bp.route('/api/results/<target>/holygrail', methods=['GET'])
@error_handler
def api_byovd_info(target):
    app = current_app
    app.logger.debug(f"Fetching BYOVD info for target: {target}")
    result_path = path_manager.find_file_by_hash(target, app.config['utils']['result_folder'])
    if not result_path:
        app.logger.warning(f"BYOVD info not found for target: {target}")
        return jsonify({'error': 'File info not found'}), 404

    file_info_path = os.path.join(result_path, 'byovd_results.json')
    if not os.path.exists(file_info_path):
        app.logger.warning(f"BYOVD info not found for target: {target}")
        return jsonify({'error': 'File info not found'}), 404

    with open(file_info_path, 'r') as f:
        app.logger.debug(f"Returning BYOVD info for target: {target}")
        return jsonify(json.load(f))


@api_bp.route('/api/report/<target>', methods=['GET'])
@error_handler
def generate_report(target):
    app = current_app
    deps = _deps()
    app.logger.debug(f"Generating report for target: {target}")

    data, error_msg, is_error = deps.helpers.load_analysis_data(target)
    if is_error:
        app.logger.warning(f"Error loading data for report generation: {error_msg}")
        return jsonify({'error': error_msg}), 404

    html_report = reporting.generate_html_report(
        file_info=data['file_info'],
        static_results=data['static_results'],
        dynamic_results=data['dynamic_results'],
        pid=data['pid'],
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

    app.logger.debug("Returning HTML report for display")
    return html_report


@api_bp.route('/report/<target>', methods=['GET'])
@error_handler
def report_page(target):
    app = current_app
    deps = _deps()
    app.logger.debug(f"Redirecting to download report for target: {target}")

    data, error_msg, is_error = deps.helpers.load_analysis_data(target)
    if is_error:
        app.logger.warning(f"Error loading data for report page: {error_msg}")
        return render_template('error.html', error=error_msg), 404

    return redirect(f'/api/report/{target}?download=true')
