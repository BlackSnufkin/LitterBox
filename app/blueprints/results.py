# app/blueprints/results.py
"""Result-page rendering and file/PID summary aggregation."""
import os

from flask import Blueprint, current_app, jsonify, render_template

from ..services.error_handling import error_handler
from ..services.rendering import render_file_results, render_pid_results
from ..services.summary import process_file_summary, process_pid_summary

results_bp = Blueprint('results', __name__)


def _deps():
    return current_app.extensions['litterbox']


@results_bp.route('/results/<target>/<analysis_type>', methods=['GET'])
@error_handler
def get_analysis_results(target, analysis_type):
    app = current_app
    deps = _deps()
    app.logger.debug(
        f"Received analysis results request for target: {target}, "
        f"analysis_type: {analysis_type}"
    )

    data, error_msg, is_error = deps.helpers.load_analysis_data(target)
    if is_error:
        app.logger.debug(f"Error loading data: {error_msg}")
        return render_template('error.html', error=error_msg), 404

    risk_score, risk_level, _ = deps.helpers.calculate_and_add_risk(data)
    app.logger.debug(f"Calculated risk assessment - Score: {risk_score}, Level: {risk_level}")

    if data['is_pid']:
        return render_pid_results(data, deps.helpers)
    return render_file_results(data, analysis_type, deps.helpers)


@results_bp.route('/summary', methods=['GET'])
def summary_page():
    return render_template('summary.html')


@results_bp.route('/files', methods=['GET'])
@error_handler
def get_files_summary():
    app = current_app
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
            process_pid_summary(item, item_path, pid_based_summary, app.logger)
        else:
            process_file_summary(item, item_path, file_based_summary, app.logger)

    driver_based_summary = {}
    payload_based_summary = {}

    for key, file_data in file_based_summary.items():
        filename = file_data.get('filename', '')
        if filename.lower().endswith('.sys'):
            driver_based_summary[key] = file_data
        else:
            payload_based_summary[key] = file_data

    for driver_key, driver_data in driver_based_summary.items():
        app.logger.debug(f"All driver data keys: {list(driver_data.keys())}")
        app.logger.debug(f"Full driver data: {driver_data}")

    return jsonify({
        'status': 'success',
        'driver_based': {
            'count': len(driver_based_summary),
            'drivers': driver_based_summary,
        },
        'payload_based': {
            'count': len(payload_based_summary),
            'payloads': payload_based_summary,
        },
        'pid_based': {
            'count': len(pid_based_summary),
            'processes': pid_based_summary,
        },
    })
