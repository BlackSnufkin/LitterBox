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


@api_bp.route('/api/results/static/<target>', methods=['GET'])
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


@api_bp.route('/api/results/dynamic/<target>', methods=['GET'])
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


@api_bp.route('/api/results/info/<target>', methods=['GET'])
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


@api_bp.route('/api/results/holygrail/<target>', methods=['GET'])
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


@api_bp.route('/api/edr/profiles', methods=['GET'])
@error_handler
def api_edr_profiles():
    """List the EDR profiles loaded at boot. The upload page uses this to
    render one 'Run with X' button per profile. Secrets (apikey) are never
    surfaced — see registry.list_profiles()."""
    deps = _deps()
    return jsonify({'profiles': deps.edr_registry.list_profiles()})


@api_bp.route('/api/edr/fibratus/<profile>/alerts/since', methods=['GET'])
@error_handler
def api_fibratus_alerts_passthrough(profile):
    """Test/debug passthrough — query the Whiskers agent's
    `/api/alerts/fibratus/since` endpoint for a registered profile.

    Lets operators verify the Fibratus-on-VM → event-log → Whiskers wire
    is healthy without dispatching a payload. Same query params (`from`,
    `until` — ISO8601). Returns whatever the agent returned, or 404 if
    the named profile isn't registered or isn't kind=fibratus.
    """
    from ..analyzers.edr.agent_client import AgentClient, AgentError, AgentUnreachable

    deps = _deps()
    p = deps.edr_registry.get_profile(profile)
    if p is None:
        return jsonify({'error': f'Unknown EDR profile: {profile}'}), 404
    if p.kind != 'fibratus':
        return jsonify({
            'error': f'Profile {profile!r} is kind={p.kind!r}, not fibratus',
        }), 400

    since = request.args.get('from')
    if not since:
        return jsonify({'error': 'missing required `from` query param (ISO8601)'}), 400
    from datetime import datetime, timezone
    until = request.args.get('until') or datetime.now(timezone.utc).isoformat()

    agent = AgentClient(p.agent_url)
    try:
        return jsonify(agent.get_fibratus_alerts(since, until))
    except AgentUnreachable as exc:
        return jsonify({'error': f'agent unreachable: {exc}'}), 502
    except AgentError as exc:
        return jsonify({'error': f'agent error: {exc}'}), 502


@api_bp.route('/api/edr/agents/status', methods=['GET'])
@error_handler
def api_edr_agents_status():
    """Latest reachability snapshot for every registered EDR profile.

    Reads the cached probe result (refreshed in the background by
    `services.edr_health`'s poller, with a 30s TTL on the cache itself).
    Cold-start cache misses fall through to a synchronous probe — first
    request after boot waits one probe cycle, every subsequent dashboard
    fetch is instant.

    Pass `?refresh=1` to force a synchronous re-probe (debug aid).
    """
    from ..services import edr_health

    deps = _deps()
    profiles = list(deps.edr_registry._PROFILES.values())  # internal accessor — same module
    force = request.args.get('refresh') == '1'
    return jsonify(edr_health.get_status_snapshot(profiles, force_refresh=force))


@api_bp.route('/api/results/edr/<profile>/<target>', methods=['GET'])
@error_handler
def api_edr_results(target, profile):
    """Read the saved findings for a specific EDR profile run on `target`."""
    app = current_app
    app.logger.debug(f"Fetching EDR results for target={target} profile={profile}")
    result_path = path_manager.find_file_by_hash(target, app.config['utils']['result_folder'])
    if not result_path:
        return jsonify({'error': 'Results not found'}), 404

    edr_path = os.path.join(result_path, f'edr_{profile}_results.json')
    if not os.path.exists(edr_path):
        return jsonify({'error': f'EDR results for profile {profile!r} not found'}), 404

    with open(edr_path, 'r') as f:
        return jsonify(json.load(f))


@api_bp.route('/api/results/edr/<target>', methods=['GET'])
@error_handler
def api_edr_index(target):
    """List which EDR profiles have saved results for `target`."""
    app = current_app
    result_path = path_manager.find_file_by_hash(target, app.config['utils']['result_folder'])
    if not result_path:
        return jsonify({'profiles': []})

    profiles = []
    prefix, suffix = 'edr_', '_results.json'
    for entry in os.listdir(result_path):
        if entry.startswith(prefix) and entry.endswith(suffix):
            profiles.append(entry[len(prefix):-len(suffix)])
    return jsonify({'profiles': sorted(profiles)})


@api_bp.route('/api/results/risk/<target>', methods=['GET'])
@error_handler
def api_risk_assessment(target):
    """Return the computed detection assessment (score, level, triggering indicators) for a target."""
    app = current_app
    deps = _deps()
    app.logger.debug(f"Fetching risk assessment for target: {target}")

    data, error_msg, is_error = deps.helpers.load_analysis_data(target)
    if is_error:
        app.logger.warning(f"Error loading data for risk assessment: {error_msg}")
        return jsonify({'error': error_msg}), 404

    risk_score, risk_level, risk_factors = deps.helpers.calculate_and_add_risk(data)
    app.logger.debug(
        f"Risk assessment calculated - score={risk_score}, level={risk_level}"
    )
    return jsonify({
        'risk_score': risk_score,
        'risk_level': risk_level,
        'risk_factors': risk_factors,
    })


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
        byovd_results=data.get('byovd_results'),
        edr_results=data.get('edr_results'),
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
