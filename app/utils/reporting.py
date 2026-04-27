# app/utils/reporting.py
"""HTML report rendering."""
import datetime as dt

from flask import render_template

from .json_helpers import extract_detection_counts, format_size
from .risk_analyzer import calculate_risk, get_risk_level


def generate_html_report(file_info=None, static_results=None,
                         dynamic_results=None, pid=None):
    """Render the report.html template with risk + detection summary."""
    is_process_analysis = pid is not None and not file_info
    analysis_type = 'process' if is_process_analysis else 'file'

    risk_score, risk_factors = calculate_risk(
        analysis_type=analysis_type,
        file_info=file_info,
        static_results=static_results,
        dynamic_results=dynamic_results,
    )
    risk_level = get_risk_level(risk_score)

    detections = {}
    if static_results or dynamic_results:
        detections = extract_detection_counts(dynamic_results or static_results)

    if dynamic_results and is_process_analysis:
        if 'process_output' not in dynamic_results:
            dynamic_results['process_output'] = {
                'had_output': False,
                'output': '',
                'stdout': '',
                'stderr': '',
            }

    return render_template(
        "report.html",
        generated_on=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        is_process_analysis=is_process_analysis,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_factors=risk_factors,
        detections=detections,
        file_info=file_info,
        static_results=static_results,
        dynamic_results=dynamic_results,
        pid=pid,
        format_size=format_size,
    )
