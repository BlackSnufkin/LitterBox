# app/services/tool_check.py
"""Tool/path validation helpers for the /health endpoint."""
import os


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
