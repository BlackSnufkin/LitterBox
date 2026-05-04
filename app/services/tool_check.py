# app/services/tool_check.py
"""Tool/path validation + inventory helpers for the /health endpoint."""
import os


def scanner_inventory(analysis_cfg):
    """Per-scanner inventory: enabled flag, configured path, exists-on-disk.

    Walks the static + dynamic + holygrail sections of analysis config and
    returns `(rows, counts)` for the unified /health response. Same shape as
    the (now-removed) /api/system/scanners endpoint.
    """
    def _row(group, name, scanner_cfg):
        tool_path = (scanner_cfg or {}).get('tool_path', '').strip()
        enabled = bool((scanner_cfg or {}).get('enabled', False))
        exists = bool(tool_path) and os.path.isfile(tool_path)
        return {
            'group': group,
            'name': name,
            'enabled': enabled,
            'tool_path': tool_path,
            'exists': exists,
            'status': (
                'ok' if enabled and exists else
                'missing' if enabled and not exists else
                'disabled'
            ),
        }

    cfg = analysis_cfg or {}
    rows = []
    for group_key in ('static', 'dynamic'):
        group_cfg = cfg.get(group_key) or {}
        for scanner_name, scanner_cfg in group_cfg.items():
            if isinstance(scanner_cfg, dict):
                rows.append(_row(group_key, scanner_name, scanner_cfg))

    holygrail = cfg.get('holygrail')
    if isinstance(holygrail, dict):
        rows.append(_row('holygrail', 'holygrail', holygrail))

    counts = {
        'total':    len(rows),
        'ok':       sum(1 for r in rows if r['status'] == 'ok'),
        'missing':  sum(1 for r in rows if r['status'] == 'missing'),
        'disabled': sum(1 for r in rows if r['status'] == 'disabled'),
    }
    return rows, counts


def check_analysis_tool(section, tool_name, issues, logger):
    """Append issues for a static or dynamic analysis tool."""
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


def check_holygrail_tool(holygrail_config, issues, logger):
    """Append issues for HolyGrail kernel-driver analyzer config."""
    if not holygrail_config.get('enabled', False):
        return

    logger.debug("Checking HolyGrail tool configuration")

    tool_path = holygrail_config.get('tool_path')
    if not tool_path:
        issues.append("HolyGrail: tool path not configured")
    elif not os.path.isfile(tool_path):
        issues.append(f"HolyGrail: tool not found at {tool_path}")

    policies_path = holygrail_config.get('policies_path')
    if not policies_path:
        issues.append("HolyGrail: policies path not configured")
    elif not os.path.isdir(policies_path):
        issues.append(f"HolyGrail: policies directory not found at {policies_path}")

    results_path = holygrail_config.get('results_path')
    if not results_path:
        issues.append("HolyGrail: results path not configured")
    elif not os.path.exists(results_path):
        try:
            os.makedirs(results_path, exist_ok=True)
            logger.debug(f"Created HolyGrail results directory: {results_path}")
        except Exception as e:
            issues.append(
                f"HolyGrail: unable to create results directory {results_path}: {str(e)}"
            )

    timeout = holygrail_config.get('timeout')
    if timeout is None:
        issues.append("HolyGrail: timeout not configured")
    elif not isinstance(timeout, (int, float)) or timeout <= 0:
        issues.append("HolyGrail: invalid timeout value")
