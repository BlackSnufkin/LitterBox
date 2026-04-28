# app/services/rendering.py
"""Result-page render helpers for the /results/<target>/<type> endpoint."""
import os

from flask import current_app, render_template

from ..utils import json_helpers, risk_analyzer


def is_kernel_driver_file(filename):
    """Check if a filename looks like a kernel driver."""
    if not filename:
        return False
    return filename.lower().endswith('.sys')


def render_pid_results(data, route_helpers):
    detections = route_helpers.get_detection_counts(data)
    current_app.logger.debug(f"Extracted detection counts: {detections}")

    risk_data = data['dynamic_results']['risk_assessment']
    return render_template(
        'dynamic_info.html',
        file_info=None,
        analysis_results=data['dynamic_results'],
        yara_detections=detections['yara'],
        pesieve_detections=detections['pesieve'],
        moneta_detections=detections['moneta'],
        patriot_detections=detections['patriot'],
        hsb_detections=detections['hsb'],
        risk_level=risk_data['level'],
        risk_score=risk_data['score'],
        risk_factors=risk_data['factors'],
    )


def render_file_results(data, analysis_type, route_helpers):
    if analysis_type == 'info':
        return render_file_info(data)
    if analysis_type == 'byovd':
        return render_byovd_results(data)
    if analysis_type in ['static', 'dynamic']:
        return render_analysis_info(data, analysis_type, route_helpers)

    current_app.logger.debug(f"Invalid analysis type received: {analysis_type}")
    return render_template('error.html', error='Invalid analysis type.'), 400


def render_byovd_results(data):
    """Render driver-specific BYOVD analysis results."""
    current_app.logger.debug("Rendering BYOVD (driver) results")

    file_info = data['file_info']
    filename = file_info.get('original_name', '')
    if not is_kernel_driver_file(filename):
        current_app.logger.warning(f"BYOVD analysis requested for non-driver file: {filename}")
        return render_template(
            'error.html',
            error='BYOVD analysis is only available for driver files (.sys)',
        ), 400

    result_path = data['result_path']
    holygrail_path = os.path.join(result_path, 'byovd_results.json')

    holygrail_results = None
    if os.path.exists(holygrail_path):
        holygrail_results = json_helpers.load_json_file(holygrail_path)
        current_app.logger.debug(f"Loaded HolyGrail results from: {holygrail_path}")
    else:
        current_app.logger.debug(f"No HolyGrail results found at: {holygrail_path}")

    current_app.logger.debug("Rendering byovd_info.html template")
    return render_template(
        'byovd_info.html',
        file_info=file_info,
        holygrail_results=holygrail_results,
        has_holygrail_analysis=holygrail_results is not None,
    )


def render_file_info(data):
    file_info = data['file_info']
    logger = current_app.logger

    if 'pe_info' in file_info:
        pe_info = file_info['pe_info']

        for section in pe_info['sections']:
            section['entropy_risk'] = risk_analyzer.get_entropy_risk_level(section['entropy'])
            logger.debug(
                f"Calculated entropy risk for section {section.get('name', 'unknown')}: "
                f"{section['entropy_risk']}"
            )

        grouped_imports = {}
        for imp in pe_info.get('suspicious_imports', []):
            dll = imp['dll']
            grouped_imports.setdefault(dll, []).append(imp)
        pe_info['grouped_suspicious_imports'] = grouped_imports
        logger.debug(f"Grouped suspicious imports for {len(grouped_imports)} DLLs")

        if 'checksum_info' in pe_info:
            checksum = pe_info['checksum_info']
            checksum['stored_checksum'] = json_helpers.format_hex(checksum['stored_checksum'])
            checksum['calculated_checksum'] = json_helpers.format_hex(
                checksum['calculated_checksum']
            )
            logger.debug(
                f"Formatted checksum values - Stored: {checksum['stored_checksum']}, "
                f"Calculated: {checksum['calculated_checksum']}"
            )

    logger.debug("Rendering file_info.html template")
    return render_template(
        'file_info.html',
        file_info=file_info,
        entropy_risk_levels={'High': 7.2, 'Medium': 6.8, 'Low': 0},
    )


def render_analysis_info(data, analysis_type, route_helpers):
    results_key = f'{analysis_type}_results'
    analysis_results = data[results_key]

    if not analysis_results:
        current_app.logger.debug(f"No {analysis_type} analysis results found")
        return render_template(
            'error.html', error=f'No {analysis_type} analysis results found',
        ), 404

    current_app.logger.debug(f"Successfully loaded {analysis_type} analysis results")
    # Counts MUST come from the same scope we're rendering. Using the shared
    # route_helpers.get_detection_counts(data) returns dynamic counts whenever
    # a dynamic scan exists, which is wrong on the /static page (the row's
    # match list is static but the count is dynamic, so YARA can read
    # "Detected / 3" with "No rules matched" right next to it).
    detections = json_helpers.extract_detection_counts(analysis_results)

    if analysis_type == 'static':
        return render_static_results(data, analysis_results, detections)
    return render_dynamic_results(data, analysis_results, detections)


def render_static_results(data, analysis_results, detections):
    checkplz_detections = 0
    checkplz_findings = analysis_results.get('checkplz', {}).get('findings', {})
    if isinstance(checkplz_findings, dict):
        checkplz_detections = 1 if checkplz_findings.get('initial_threat') else 0
    current_app.logger.debug(f"Checkplz detections: {checkplz_detections}")

    formatted_duration = format_scan_duration(analysis_results)

    current_app.logger.debug("Rendering static_info.html template")
    return render_template(
        'static_info.html',
        file_info=data['file_info'],
        analysis_results=analysis_results,
        yara_detections=detections['yara'],
        checkplz_detections=checkplz_detections,
        stringnalyzer_results=analysis_results.get('stringnalyzer', {}),
        scan_duration=formatted_duration,
    )


def render_dynamic_results(data, analysis_results, detections):
    current_app.logger.debug("Rendering dynamic_info.html template")
    return render_template(
        'dynamic_info.html',
        file_info=data['file_info'],
        analysis_results=analysis_results,
        yara_detections=detections['yara'],
        pesieve_detections=detections['pesieve'],
        moneta_detections=detections['moneta'],
        patriot_detections=detections['patriot'],
        hsb_detections=detections['hsb'],
    )


def format_scan_duration(analysis_results):
    logger = current_app.logger
    try:
        raw_duration = analysis_results.get('analysis_metadata', {}).get('total_duration', {})
        logger.debug(f"Raw scan duration value: {raw_duration}")
        scan_duration = float(raw_duration or 0)

        minutes = int(scan_duration // 60)
        seconds = int(scan_duration % 60)
        milliseconds = int((scan_duration % 1) * 1000)
        formatted = f"{minutes:02d}:{seconds:02d}.{milliseconds:03d}"
        logger.debug(f"Formatted scan duration: {formatted}")
        return formatted
    except (TypeError, ValueError, AttributeError) as e:
        logger.error(f"Error formatting scan duration: {e}")
        return "00:00.000"
