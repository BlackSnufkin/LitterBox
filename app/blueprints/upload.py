# app/blueprints/upload.py
"""Index dashboard, upload drop-zone, and generic file uploads."""
from flask import Blueprint, current_app, jsonify, render_template, request

from ..services.error_handling import error_handler
from ..utils import file_io, validators

upload_bp = Blueprint('upload', __name__)


@upload_bp.route('/')
def index():
    """System health dashboard: agents + scanner availability.
    Live data is fetched async by the page's JS via /api/edr/agents/status
    and /api/system/scanners."""
    deps = current_app.extensions['litterbox']
    return render_template(
        'dashboard.html',
        config=current_app.config,
        edr_profiles=deps.edr_registry.list_profiles(),
    )


@upload_bp.route('/upload', methods=['GET'])
def upload_page():
    """Upload drop-zone — renders the analysis-mode picker."""
    deps = current_app.extensions['litterbox']
    return render_template(
        'upload.html',
        config=current_app.config,
        edr_profiles=deps.edr_registry.list_profiles(),
    )


@upload_bp.route('/upload', methods=['POST'])
@error_handler
def upload_file():
    app = current_app
    app.logger.debug("Received a file upload request.")

    if 'file' not in request.files:
        app.logger.debug("No file part in the request.")
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        app.logger.debug("No file selected for upload.")
        return jsonify({'error': 'No selected file'}), 400

    if not (file and validators.allowed_file(file.filename, app.config['utils']['allowed_extensions'])):
        app.logger.debug(f"File type of '{file.filename}' is not allowed.")
        return jsonify({'error': 'File type not allowed'}), 400

    app.logger.debug(f"File '{file.filename}' is allowed. Attempting to save.")
    file_info = file_io.save_uploaded_file(file, app.config)
    app.logger.debug(f"File '{file.filename}' uploaded and saved successfully.")
    return jsonify({
        'message': 'File uploaded successfully',
        'file_info': file_info,
    }), 200
