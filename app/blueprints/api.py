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


@api_bp.route('/api/edr/profiles', methods=['GET'])
@error_handler
def api_edr_profiles():
    """List the EDR profiles loaded at boot. The upload page uses this to
    render one 'Run with X' button per profile. Secrets (apikey) are never
    surfaced — see registry.list_profiles()."""
    deps = _deps()
    return jsonify({'profiles': deps.edr_registry.list_profiles()})


@api_bp.route('/api/edr/agents/status', methods=['GET'])
@error_handler
def api_edr_agents_status():
    """Live probe of every registered EDR profile.

    For each profile we hit the agent's /api/info + /api/lock/status and
    the Elastic stack's `GET /` ping in parallel. Each probe is bounded
    by a tight timeout so an unreachable agent doesn't stall the whole
    page. Used by /whiskers to render the inventory + live status.
    """
    from concurrent.futures import ThreadPoolExecutor
    from ..analyzers.edr.agent_client import AgentClient, AgentError, AgentUnreachable
    from ..analyzers.edr.elastic_client import ElasticClient, ElasticError, ElasticUnreachable

    deps = _deps()
    profiles = list(deps.edr_registry._PROFILES.values())  # internal accessor — same module

    def probe(p):
        agent = AgentClient(p.agent_url, timeout=4)
        elastic = ElasticClient(
            p.elastic_url, p.elastic_apikey,
            verify_tls=p.elastic_verify_tls, timeout=5,
        )
        agent_info, agent_err, lock = None, None, None
        try:
            agent_info = agent.get_info()
            try:
                lock = agent.lock_status()
            except (AgentUnreachable, AgentError):
                pass
        except AgentUnreachable as e:
            agent_err = f"unreachable: {e}"
        except AgentError as e:
            agent_err = f"error: {e}"

        elastic_info, elastic_err = None, None
        try:
            elastic_info = elastic.ping()
        except ElasticUnreachable as e:
            elastic_err = f"unreachable: {e}"
        except ElasticError as e:
            elastic_err = f"error: {e}"

        return {
            "name": p.name,
            "display_name": p.display_name,
            "type": "elastic-defend",
            "agent_url": p.agent_url,
            "elastic_url": p.elastic_url,
            "agent": {
                "reachable": agent_info is not None,
                "error": agent_err,
                "hostname": (agent_info or {}).get("hostname"),
                "os_version": (agent_info or {}).get("os_version"),
                "agent_version": (agent_info or {}).get("agent_version"),
            },
            "lock": lock,
            "elastic": {
                "reachable": elastic_info is not None,
                "error": elastic_err,
                "cluster_name": (elastic_info or {}).get("cluster_name"),
                "version": ((elastic_info or {}).get("version") or {}).get("number"),
            },
        }

    if not profiles:
        return jsonify({"agents": []})

    # Probe in parallel — total wall time is the slowest probe, not sum of all.
    with ThreadPoolExecutor(max_workers=min(8, len(profiles))) as pool:
        results = list(pool.map(probe, profiles))
    return jsonify({"agents": results})


@api_bp.route('/api/results/<target>/edr/<profile>', methods=['GET'])
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


@api_bp.route('/api/results/<target>/edr', methods=['GET'])
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


@api_bp.route('/api/results/<target>/risk', methods=['GET'])
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
