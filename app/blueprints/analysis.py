# app/blueprints/analysis.py
"""PID validation, static/dynamic analysis dispatch, BYOVD driver analysis."""
import logging
import os

from flask import Blueprint, current_app, jsonify, render_template, request

from ..analyzers.holygrail import HolyGrailAnalyzer
from ..services.error_handling import error_handler
from ..services.rendering import is_kernel_driver_file
from ..utils import file_io, path_manager, validators

analysis_bp = Blueprint('analysis', __name__)

# Module-level logger for use in background-thread callbacks where the
# Flask app context (and thus current_app.logger) isn't available.
_bg_logger = logging.getLogger(__name__)


def _deps():
    return current_app.extensions['litterbox']


@analysis_bp.route('/validate/<pid>', methods=['POST'])
@error_handler
def validate_process(pid):
    app = current_app
    app.logger.debug(f"Received PID validation request for PID: {pid}")

    is_valid, error_msg = validators.validate_pid(pid)
    if not is_valid:
        app.logger.debug(f"PID {pid} is invalid. Reason: {error_msg}")
        return jsonify({'error': error_msg}), 404

    app.logger.debug(f"PID {pid} is valid.")
    return jsonify({'status': 'valid'}), 200


@analysis_bp.route('/analyze/<analysis_type>/<target>', methods=['GET', 'POST'])
@error_handler
def analyze_file(analysis_type, target):
    app = current_app
    app.logger.debug(
        f"Received request to analyze. Analysis type: {analysis_type}, Target: {target}"
    )

    if request.method == 'GET':
        app.logger.debug(
            f"GET request received for analysis type: {analysis_type}, Target: {target}"
        )
        return render_template('results.html', analysis_type=analysis_type, file_hash=target)

    app.logger.debug(f"POST request received. Performing {analysis_type} analysis.")
    is_pid = analysis_type == 'dynamic' and target.isdigit()

    if is_pid:
        return _perform_pid_analysis(target)
    return _perform_file_analysis(analysis_type, target)


def _perform_pid_analysis(pid):
    app = current_app
    deps = _deps()

    is_valid, error_msg = validators.validate_pid(pid)
    if not is_valid:
        app.logger.debug(f"PID validation failed for PID {pid}. Reason: {error_msg}")
        return jsonify({'error': error_msg}), 404

    result_folder = os.path.join(app.config['utils']['result_folder'], f'dynamic_{pid}')
    os.makedirs(result_folder, exist_ok=True)

    cmd_args = _extract_and_validate_args(request, app.logger)

    app.logger.debug(f"Performing dynamic analysis on PID: {pid}")
    results = deps.manager.run_dynamic_analysis(pid, True, cmd_args)

    return _handle_analysis_results(results, result_folder, 'dynamic_analysis_results.json')


def _perform_file_analysis(analysis_type, target):
    app = current_app
    deps = _deps()

    if analysis_type == 'static' and target.isdigit():
        app.logger.debug(f"Static analysis requested on PID {target}. This is invalid.")
        return jsonify({'error': 'Cannot perform static analysis on PID'}), 400

    if analysis_type not in ['static', 'dynamic']:
        app.logger.debug(f"Invalid analysis type received: {analysis_type}")
        return jsonify({'error': 'Invalid analysis type'}), 400

    file_path = path_manager.find_file_by_hash(target, app.config['utils']['upload_folder'])
    result_path = path_manager.find_file_by_hash(target, app.config['utils']['result_folder'])

    if not file_path:
        app.logger.debug(f"File with hash {target} not found in upload folder.")
        return jsonify({'error': 'File not found'}), 404

    app.logger.debug(f"File found at: {file_path}, Results will be saved to: {result_path}")

    if analysis_type == 'static':
        app.logger.debug(f"Performing static analysis on file: {file_path}")
        results = deps.manager.run_static_analysis(file_path)
        results_file = 'static_analysis_results.json'
    else:
        cmd_args = _extract_and_validate_args(request, app.logger)
        app.logger.debug(f"Performing dynamic analysis on target: {file_path}, is_pid: False")
        results = deps.manager.run_dynamic_analysis(file_path, False, cmd_args)
        results_file = 'dynamic_analysis_results.json'

    return _handle_analysis_results(results, result_path, results_file)


def _extract_and_validate_args(req, logger):
    try:
        request_data = req.get_json() or {}
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


def _handle_analysis_results(results, result_path, results_filename):
    app = current_app
    deps = _deps()

    deps.helpers.save_analysis_results(results, result_path, results_filename)

    if results.get('status') == 'early_termination':
        app.logger.error("Process terminated early during initialization")
        return jsonify({
            'status': 'early_termination',
            'error': results.get('error', {}).get('message', 'Process terminated early'),
            'details': {
                'termination_time': results.get('error', {}).get('termination_time'),
                'init_time': results.get('error', {}).get('init_time'),
                'message': results.get('error', {}).get('details'),
            },
        }), 202

    if results.get('status') == 'error':
        app.logger.debug("Analysis completed with errors.")
        return jsonify({
            'status': 'error',
            'error': results.get('error', {}).get('message', 'Analysis failed'),
            'details': results.get('error', {}).get('details'),
        }), 500

    app.logger.debug("Analysis completed successfully.")
    return jsonify({'status': 'success', 'results': results})


@analysis_bp.route('/analyze/all/<target>', methods=['GET'])
def analyze_all_page(target):
    """Coordinator page for the "All" pipeline. The page itself is a
    progress shell — orchestration happens in JS, hitting the existing
    /analyze/static, /analyze/edr/<profile>, and /analyze/dynamic
    endpoints. No new analyzer code on the server side."""
    deps = current_app.extensions['litterbox']
    return render_template(
        'analyze_all.html',
        config=current_app.config,
        file_hash=target,
        edr_profiles=deps.edr_registry.list_profiles(),
    )


@analysis_bp.route('/whiskers', methods=['GET'])
def whiskers_page():
    """Render the Whiskers (EDR agents) inventory page. Live status data
    is fetched async by the page's JS via /api/edr/agents/status."""
    deps = current_app.extensions['litterbox']
    return render_template(
        'agents.html',
        config=current_app.config,
        edr_profiles=deps.edr_registry.list_profiles(),
    )


@analysis_bp.route('/analyze/edr/<profile>/<target>', methods=['GET', 'POST'])
@error_handler
def analyze_edr(profile, target):
    """Dispatch a payload to a registered EDR profile.

    GET  -> render results.html with analysis_type='edr' (the JS then POSTs).
    POST -> call edr_registry.dispatch(profile, file_path), save the result
            as edr_<profile>_results.json under the file's result folder, and
            return the findings JSON.
    """
    app = current_app
    deps = _deps()
    app.logger.debug(f"Received EDR analysis request — profile={profile} target={target}")

    if request.method == 'GET':
        return render_template(
            'results.html',
            analysis_type='edr',
            file_hash=target,
            edr_profile=profile,
        )

    if not deps.edr_registry.get_profile(profile):
        app.logger.warning(f"Unknown EDR profile: {profile}")
        return jsonify({'error': f'Unknown EDR profile: {profile}'}), 404

    if target.isdigit():
        return jsonify({'error': 'EDR analysis requires a file (not a PID)'}), 400

    file_path = path_manager.find_file_by_hash(target, app.config['utils']['upload_folder'])
    if not file_path:
        app.logger.debug(f"File with hash {target} not found in upload folder.")
        return jsonify({'error': 'File not found'}), 404

    result_path = path_manager.find_file_by_hash(target, app.config['utils']['result_folder'])
    if not result_path:
        app.logger.warning(f"Result path not found for hash: {target}")
        return jsonify({'error': 'Result path not found'}), 404

    # Pull cmd args from the POST body (validated/sanitized like the
    # dynamic-analysis route does) and join into the single string
    # AgentClient.exec expects. For DLL targets the first token is the
    # exported entry point — Whiskers wraps with rundll32 server-side.
    cmd_args = _extract_and_validate_args(request, app.logger)
    executable_args = ' '.join(cmd_args) if cmd_args else None

    app.logger.debug(
        f"Dispatching to EDR profile {profile!r} with payload {file_path} "
        f"args={executable_args!r}"
    )
    results_filename = f'edr_{profile}_results.json'

    # Phase 2 callback — runs on a background thread when alerts arrive.
    # Captures `result_path` / `results_filename` / `helpers` via closure.
    # We log via `_bg_logger` (stdlib logging) instead of `app.logger`
    # because the Flask LocalProxy requires an app context that the
    # background thread doesn't have.
    helpers = deps.helpers
    def _on_phase_2_done(phase_2_result):
        try:
            helpers.save_analysis_results(
                phase_2_result, result_path, results_filename
            )
            _bg_logger.debug(
                "EDR Phase 2 complete for %s/%s: status=%s alerts=%s",
                profile, target,
                phase_2_result.get('status'),
                phase_2_result.get('summary', {}).get('total_alerts'),
            )
        except Exception:
            _bg_logger.exception(
                "Failed to save EDR Phase 2 result for %s/%s", profile, target
            )

    try:
        results = deps.edr_registry.dispatch_split(
            profile, file_path, app.config, _on_phase_2_done,
            executable_args=executable_args,
        )
    except Exception as e:
        app.logger.error(f"EDR dispatch failed: {e}", exc_info=True)
        return jsonify({'status': 'error', 'error': str(e)}), 500

    status = results.get('status', 'completed')

    # Persist the Phase 1 snapshot ONLY when something real actually
    # happened on the agent. Pre-execution transport failures
    # (agent_unreachable, busy, error) leave us with an empty error
    # envelope that has no execution / alerts / hostname — saving it
    # would just clutter the saved-view route later with a fake
    # "result" that's really just the error message. The dispatch
    # error is still surfaced to the caller via the HTTP response.
    PRE_EXEC_FAILURES = {'agent_unreachable', 'busy', 'error'}
    if status not in PRE_EXEC_FAILURES:
        # If Phase 2 is in flight, the background thread will overwrite
        # this file when it completes; the frontend polls the GET
        # endpoint to pick up the final state.
        deps.helpers.save_analysis_results(results, result_path, results_filename)
    else:
        app.logger.debug(
            f"Skipping save for EDR profile={profile} target={target}: "
            f"status={status} (pre-execution failure)"
        )

    payload = {'edr': results}
    if status in ('error', 'agent_unreachable'):
        return jsonify({'status': status, 'results': payload}), 502
    if status == 'busy':
        return jsonify({'status': status, 'results': payload}), 409

    return jsonify({'status': 'success', 'results': payload})


@analysis_bp.route('/holygrail', methods=['GET', 'POST'])
@error_handler
def holygrail():
    """
    holygrail endpoint for kernel driver analysis.

    GET: Render upload page or run BYOVD analysis when a `hash` query is given.
    POST: Save an uploaded kernel driver (.sys).
    """
    app = current_app
    app.logger.debug("Accessed holygrail endpoint")

    if request.method == 'GET':
        target_hash = request.args.get('hash')

        if target_hash:
            return _run_byovd_analysis(target_hash)

        app.logger.debug("Rendering holygrail upload page")
        return render_template('holygrail.html')

    if 'file' not in request.files:
        app.logger.debug("No file part in holygrail request")
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        app.logger.debug("No file selected in holygrail upload")
        return jsonify({'error': 'No selected file'}), 400

    if not is_kernel_driver_file(file.filename):
        app.logger.debug(f"File '{file.filename}' is not a valid kernel driver format")
        return jsonify({'error': 'File must be a kernel driver (.sys)'}), 400

    app.logger.debug(f"Kernel driver file '{file.filename}' uploaded. Saving...")
    file_info = file_io.save_uploaded_file(file, app.config)

    app.logger.debug(f"Kernel driver '{file.filename}' saved successfully")
    return jsonify({
        'message': 'Kernel driver uploaded successfully',
        'file_info': file_info,
        'next_step': 'Ready for BYOVD analysis',
    }), 200


def _run_byovd_analysis(target_hash):
    app = current_app
    deps = _deps()
    app.logger.debug(f"Starting BYOVD analysis for hash: {target_hash}")

    try:
        file_path = path_manager.find_file_by_hash(target_hash, app.config['utils']['upload_folder'])
        if not file_path:
            app.logger.error(f"Driver file not found for hash: {target_hash}")
            return jsonify({'status': 'error', 'error': 'Driver file not found'}), 404

        app.logger.debug(f"Found driver file: {file_path}")

        result_path = path_manager.find_file_by_hash(target_hash, app.config['utils']['result_folder'])
        if not result_path:
            app.logger.error(f"Result path not found for hash: {target_hash}")
            return jsonify({'status': 'error', 'error': 'Result path not found'}), 404

        app.logger.debug(f"Results will be saved to: {result_path}")

        analyzer = HolyGrailAnalyzer(app.config, logger=app.logger)
        results = analyzer.analyze(file_path)

        app.logger.debug(f"Analysis completed with status: {results.get('status')}")

        if results['status'] == 'completed':
            compile_time = None
            try:
                pe = file_io.get_pe_info(file_path, app.config['utils']['malapi_path'])
                pe_info = (pe or {}).get('pe_info') or {}
                compile_time = pe_info.get('compile_time')
            except Exception as e:
                app.logger.debug(f"Compile time extraction failed: {e}")

            if compile_time:
                results['compile_time'] = compile_time
                if 'findings' in results and 'detailed_analysis' in results['findings']:
                    results['findings']['detailed_analysis']['compile_time'] = compile_time

            deps.helpers.save_analysis_results(results, result_path, 'byovd_results.json')
            app.logger.debug(f"HolyGrail results saved to: {result_path}/byovd_results.json")

            return jsonify({
                'status': 'success',
                'message': 'BYOVD analysis completed',
                'results': results,
                'compile_time': compile_time,
            })

        if results['status'] == 'disabled':
            return jsonify({
                'status': 'error',
                'message': 'holygrail analyzer is disabled in configuration',
                'error': results.get('error'),
            }), 503

        app.logger.error(f"Analysis failed: {results.get('error')}")
        return jsonify({
            'status': 'error',
            'message': results.get('error', 'Analysis failed'),
        }), 500

    except Exception as e:
        app.logger.error(f"Exception during BYOVD analysis: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Unexpected error: {str(e)}',
        }), 500
