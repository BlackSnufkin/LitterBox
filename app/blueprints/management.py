# app/blueprints/management.py
"""Cleanup, health-check, and per-file deletion endpoints."""
import glob
import os
import shutil
from datetime import datetime

from flask import Blueprint, current_app, jsonify

from ..services.error_handling import error_handler
from ..services.tool_check import check_analysis_tool, check_holygrail_tool
from ..utils import path_manager

management_bp = Blueprint('management', __name__)


def _deps():
    return current_app.extensions['litterbox']


@management_bp.route('/cleanup', methods=['POST'])
@error_handler
def cleanup():
    app = current_app
    deps = _deps()
    app.logger.debug("Starting cleanup process.")

    folders_to_clean = {
        'uploads': app.config['utils']['upload_folder'],
        'results': app.config['utils']['result_folder'],
    }

    results = deps.helpers.process_file_cleanup(folders_to_clean)

    # Doppelganger sub-folders
    doppelganger_base = app.config['analysis']['doppelganger']['db']['path']
    doppelganger_folders = [app.config['analysis']['doppelganger']['db']['blender']]

    for folder_name in doppelganger_folders:
        folder_path = os.path.join(doppelganger_base, folder_name)
        if not os.path.exists(folder_path):
            continue
        app.logger.debug(f"Cleaning doppelganger folder contents: {folder_path}")
        try:
            for f in os.listdir(folder_path):
                file_path = os.path.join(folder_path, f)
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                    results['result_cleaned'] += 1
                    app.logger.debug(f"Deleted file: {file_path}")
        except Exception as e:
            app.logger.error(f"Error accessing folder {folder_path}: {e}")
            results['errors'].append(f"Error accessing {folder_name}: {str(e)}")

    # PE-Sieve analysis sub-folders
    analysis_path = os.path.join('.', 'Scanners', 'PE-Sieve', 'Analysis')
    if os.path.exists(analysis_path):
        try:
            results['analysis_cleaned'] += deps.helpers._clean_process_folders(analysis_path)
        except Exception as e:
            app.logger.error(f"Error accessing analysis folder: {e}")
            results['errors'].append(f"Error accessing analysis folder: {str(e)}")

    # HolyGrail results
    holygrail_config = app.config.get('analysis', {}).get('holygrail', {})
    if holygrail_config.get('enabled', False):
        holygrail_results_path = holygrail_config.get('results_path')
        if holygrail_results_path and os.path.exists(holygrail_results_path):
            app.logger.debug(f"Cleaning HolyGrail results folder: {holygrail_results_path}")
            try:
                for f in os.listdir(holygrail_results_path):
                    file_path = os.path.join(holygrail_results_path, f)
                    if os.path.isfile(file_path):
                        os.unlink(file_path)
                        results['analysis_cleaned'] += 1
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                        results['analysis_cleaned'] += 1
                        app.logger.debug(f"Deleted HolyGrail result folder: {file_path}")
            except Exception as e:
                app.logger.error(
                    f"Error cleaning HolyGrail results folder {holygrail_results_path}: {e}"
                )
                results['errors'].append(f"Error cleaning HolyGrail results: {str(e)}")

    status = 'warning' if results['errors'] else 'success'
    message = (
        'Cleanup completed with some errors' if results['errors']
        else 'Cleanup completed successfully'
    )
    app.logger.debug(f"Cleanup completed. Status: {status}, Message: {message}")

    return jsonify({
        'status': status,
        'message': message,
        'details': results,
    }), 200 if status == 'success' else 207


@management_bp.route('/health', methods=['GET'])
@error_handler
def health_check():
    app = current_app
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

    for tool_name in static_section.keys():
        check_analysis_tool(static_section, tool_name, issues, app.logger)

    for tool_name in dynamic_section.keys():
        check_analysis_tool(dynamic_section, tool_name, issues, app.logger)

    check_holygrail_tool(holygrail_section, issues, app.logger)

    static_tools = {
        tool: static_section.get(tool, {}).get('enabled', False)
        for tool in static_section.keys()
    }
    dynamic_tools = {
        tool: dynamic_section.get(tool, {}).get('enabled', False)
        for tool in dynamic_section.keys()
    }
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
            'holygrail_analysis': holygrail_status,
        },
    }), 200 if status == 'ok' else 503


@management_bp.route('/file/<target>', methods=['DELETE'])
@error_handler
def delete_file(target):
    app = current_app
    app.logger.debug(f"Deleting file: {target}")
    upload_path = path_manager.find_file_by_hash(target, app.config['utils']['upload_folder'])
    result_path = path_manager.find_file_by_hash(target, app.config['utils']['result_folder'])
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
    return jsonify({
        'status': 'success',
        'message': 'File deleted successfully',
        'details': deleted,
    })
