# app/utils/risk_analyzer.py
"""Risk scoring for file, process, and BYOVD driver analyses."""


class RiskCalculator:
    """YARA + PE risk aggregation with severity weighting."""

    SEVERITY_WEIGHTS = {
        'CRITICAL': 100,
        'HIGH': 80,
        'MEDIUM': 50,
        'LOW': 20,
        'INFO': 5,
    }

    NUMERIC_SEVERITY_MAP = {
        100: 'CRITICAL',
        80: 'HIGH',
        50: 'MEDIUM',
        20: 'LOW',
        5: 'INFO',
    }

    @classmethod
    def calculate_yara_risk(cls, matches):
        if not matches:
            return 0, None

        max_severity_score = 0
        severity_counts = {level: 0 for level in cls.SEVERITY_WEIGHTS}

        for match in matches:
            meta = match.get('metadata', {})
            severity = meta.get('severity', 'MEDIUM')

            if isinstance(severity, int):
                severity = cls.NUMERIC_SEVERITY_MAP.get(severity, 'MEDIUM')
            severity = severity.upper()

            if severity in cls.SEVERITY_WEIGHTS:
                severity_counts[severity] += 1
                max_severity_score = max(max_severity_score, cls.SEVERITY_WEIGHTS[severity])

        total_score = 0
        risk_factors = []

        for severity, count in severity_counts.items():
            if count > 0:
                severity_score = cls.SEVERITY_WEIGHTS[severity]

                if count > 1:
                    additional_score = sum(severity_score * (0.5 ** i) for i in range(1, count))
                    total_score += severity_score + additional_score
                else:
                    total_score += severity_score

                risk_factors.append(
                    f"{count} {severity.lower()} severity YARA match"
                    f"{'es' if count > 1 else ''}"
                )

        normalized_score = min(100, total_score / 2)
        return normalized_score, risk_factors

    @classmethod
    def calculate_pe_risk(cls, pe_info):
        pe_risk = 0
        risk_factors = []

        high_entropy_sections = 0
        very_high_entropy_sections = 0
        for section in pe_info.get('sections', []):
            entropy = section.get('entropy', 0)
            if entropy > 7.5:
                very_high_entropy_sections += 1
                risk_factors.append(
                    f"Critical entropy in section {section.get('name', 'UNKNOWN')}: {entropy:.2f}"
                )
            elif entropy > 7.0:
                high_entropy_sections += 1
                risk_factors.append(
                    f"High entropy in section {section.get('name', 'UNKNOWN')}: {entropy:.2f}"
                )

        pe_risk += min(high_entropy_sections * 10 + very_high_entropy_sections * 20, 40)

        suspicious_imports = pe_info.get('suspicious_imports', [])
        if suspicious_imports:
            critical_functions = {
                'createremotethread', 'virtualallocex', 'writeprocessmemory',
                'ntmapviewofsection', 'zwmapviewofsection',
            }
            high_risk_functions = {
                'loadlibrarya', 'loadlibraryw', 'getprocaddress',
                'openprocess', 'virtualallocexnuma',
            }

            critical_imports = sum(
                1 for imp in suspicious_imports
                if imp.get('function', '').lower() in critical_functions
            )
            high_risk_imports = sum(
                1 for imp in suspicious_imports
                if imp.get('function', '').lower() in high_risk_functions
            )

            pe_risk += min(critical_imports * 15 + high_risk_imports * 8, 30)
            if critical_imports > 0 or high_risk_imports > 0:
                risk_factors.append(
                    f"{critical_imports} critical process manipulation and "
                    f"{high_risk_imports} sensitive dynamic loading imports observed"
                )

        if pe_info.get('checksum_info'):
            checksum = pe_info['checksum_info']
            if checksum.get('stored_checksum') != checksum.get('calculated_checksum'):
                build_with = checksum.get('build_with')
                if build_with not in ['go', 'rust']:
                    pe_risk += 25
                    risk_factors.append("PE checksum mismatch observed")

        return pe_risk, risk_factors


def calculate_yara_risk(matches):
    """Module-level alias for RiskCalculator.calculate_yara_risk."""
    return RiskCalculator.calculate_yara_risk(matches)


def get_risk_level(risk_score):
    """Convert numerical risk score to a categorical risk level."""
    if risk_score >= 75:
        return "Critical"
    elif risk_score >= 50:
        return "High"
    elif risk_score >= 25:
        return "Medium"
    else:
        return "Low"


def get_entropy_risk_level(entropy):
    """Map an entropy value to a risk band."""
    if entropy > 7.2:
        return 'High'
    elif entropy > 6.8:
        return 'Medium'
    return 'Low'


def calculate_risk(analysis_type='process', file_info=None,
                   static_results=None, dynamic_results=None,
                   byovd_results=None):
    """Unified risk calculation for file, process, and driver analyses."""
    risk_score = 0
    risk_factors = []

    if analysis_type == 'driver':
        if byovd_results:
            byovd_risk, byovd_factors = _calculate_byovd_risk(byovd_results)
            risk_factors.extend([f"BYOVD: {factor}" for factor in byovd_factors])
            final_score = round(min(max(byovd_risk, 0), 100), 2)
            return final_score, risk_factors
        else:
            return 0, ["No BYOVD analysis available"]

    weights = {
        'file': {'pe_info': 0.10, 'static': 0.50, 'dynamic': 0.40},
        'process': {'dynamic': 1.0},
    }[analysis_type]

    if analysis_type == 'file' and file_info and file_info.get('pe_info'):
        pe_risk, pe_factors = RiskCalculator.calculate_pe_risk(file_info['pe_info'])
        risk_factors.extend(pe_factors)
        risk_score += (pe_risk / 100) * weights['pe_info'] * 100

    if analysis_type == 'file' and static_results:
        static_risk, static_factors = _calculate_static_risk(static_results)
        risk_factors.extend([f"Static: {factor}" for factor in static_factors])
        risk_score += (static_risk / 100) * weights['static'] * 100

    if analysis_type in ['file', 'process'] and dynamic_results:
        dynamic_risk, dynamic_factors = _calculate_dynamic_risk(dynamic_results, analysis_type)
        risk_factors.extend([f"Dynamic: {factor}" for factor in dynamic_factors])
        risk_score += (dynamic_risk / 100) * weights['dynamic'] * 100

    risk_score = _normalize_risk_score(risk_score, analysis_type, dynamic_results, risk_factors)

    return round(min(max(risk_score, 0), 100), 2), risk_factors


def _calculate_byovd_risk(byovd_results):
    risk_score = 0
    risk_factors = []

    if not byovd_results:
        return 0, []

    findings = byovd_results.get('findings', {})
    summary = findings.get('summary', {})
    detailed = findings.get('detailed_analysis', {})

    is_lol = summary.get('is_loldriver', False)
    win10_blocked = summary.get('is_win10_blocked', False)
    win11_blocked = summary.get('is_win11_blocked', False)

    critical_imports = detailed.get('critical_imports', '')
    has_terminate_process = detailed.get('has_terminate_process', False)
    has_communication = detailed.get('has_communication', False)
    has_dangerous_imports = detailed.get('has_dangerous_imports', False)

    has_danger = bool(
        has_dangerous_imports or
        (isinstance(critical_imports, str) and critical_imports.strip()) or
        has_terminate_process or
        has_communication
    )

    if win11_blocked and win10_blocked:
        risk_factors.append("Blocked on both Windows 10 and 11 - minimal exploitation potential")
        return 0, risk_factors

    if has_danger:
        risk_score += 55
        danger_factors = []
        if has_dangerous_imports:
            danger_factors.append("critical-import flag observed")
        if critical_imports and critical_imports.strip():
            danger_factors.append("critical imports listed")
        if has_terminate_process:
            danger_factors.append("process termination capability")
        if has_communication:
            danger_factors.append("communication mechanisms")

        if danger_factors:
            risk_factors.append(f"Critical capabilities: {', '.join(danger_factors)}")

    if not win11_blocked:
        risk_score += 25
        risk_factors.append("Not blocked on Windows 11")
    else:
        risk_score -= 50
        risk_factors.append("Blocked on Windows 11")

    if not win10_blocked:
        risk_score += 20
        risk_factors.append("Not blocked on Windows 10")
    else:
        risk_score -= 20
        risk_factors.append("Blocked on Windows 10")

    if not is_lol:
        risk_score += 10
        risk_factors.append("Not listed in LOLDrivers database")
    else:
        risk_score -= 5
        risk_factors.append("Listed in LOLDrivers database")

    final_score = max(0, min(100, risk_score))

    if detailed.get('win10_block_reason'):
        risk_factors.append(f"Win10 block reason: {detailed['win10_block_reason']}")
    if detailed.get('win11_block_reason'):
        risk_factors.append(f"Win11 block reason: {detailed['win11_block_reason']}")

    return final_score, risk_factors


def _calculate_static_risk(static_results):
    static_risk = 0
    risk_factors = []

    yara_matches = static_results.get('yara', {}).get('matches', [])
    yara_score, yara_factors = calculate_yara_risk(yara_matches)
    if yara_score > 0:
        match_multiplier = min(len(yara_matches) * 0.15 + 1, 1.5)
        static_risk += yara_score * match_multiplier
        risk_factors.extend(yara_factors)

    checkplz_findings = static_results.get('checkplz', {}).get('findings', {})
    if checkplz_findings:
        threat_score = 0
        if checkplz_findings.get('initial_threat'):
            threat_score += 50
            risk_factors.append("Critical: CheckPLZ AV signature triggered")

        indicators = checkplz_findings.get('threat_indicators', [])
        if indicators:
            indicator_score = min(len(indicators) * 15, 40)
            threat_score += indicator_score
            risk_factors.append(f"{len(indicators)} additional signature indicators observed")

        static_risk += threat_score

    if static_results.get('file_entropy'):
        entropy = static_results['file_entropy']
        if entropy > 7.5:
            static_risk += 30
            risk_factors.append(f"Critical overall file entropy: {entropy:.2f}")
        elif entropy > 7.0:
            static_risk += 20
            risk_factors.append(f"High overall file entropy: {entropy:.2f}")

    return static_risk, risk_factors


def _calculate_dynamic_risk(dynamic_results, analysis_type):
    dynamic_risk = 0
    risk_factors = []

    yara_matches = dynamic_results.get('yara', {}).get('matches', [])
    yara_score, yara_factors = calculate_yara_risk(yara_matches)
    if yara_score > 0:
        dynamic_risk += yara_score
        risk_factors.extend(yara_factors)

    pesieve_findings = dynamic_results.get('pe_sieve', {}).get('findings', {})
    pesieve_suspicious = int(pesieve_findings.get('total_suspicious', 0))
    if pesieve_suspicious > 0:
        severity_multiplier = 1.5 if pesieve_findings.get('severity') == 'critical' else 1.0
        pe_sieve_score = min(
            pesieve_suspicious * (20 if analysis_type == 'file' else 15) * severity_multiplier,
            45 if analysis_type == 'file' else 30,
        )
        dynamic_risk += pe_sieve_score
        risk_factors.append(f"PE-Sieve observed {pesieve_suspicious} memory modifications")

    dynamic_risk += _calculate_memory_anomaly_risk(dynamic_results, analysis_type, risk_factors)
    dynamic_risk += _calculate_behavior_risk(dynamic_results, analysis_type, risk_factors)
    dynamic_risk += _calculate_hsb_risk(dynamic_results, analysis_type, risk_factors)
    dynamic_risk += _calculate_rededr_risk(dynamic_results, analysis_type, risk_factors)

    return dynamic_risk, risk_factors


def _calculate_rededr_risk(dynamic_results, analysis_type, risk_factors):
    """Defender-only contribution from RedEdr telemetry.

    The analyzer classifies every defender_events entry as one of:
      threat   — real detection (ThreatFound, non-empty verdict, etc.)
      scan     — Defender behavior monitor actively engaged with our process
                 (BmModuleLoad / BmNotificationHandle* / BmOpenProcess)
      internal — Defender's own state plumbing (BmInternal / BmEtw)
      other    — anything else (e.g., msmpeng ThreadStop)

    Only `threat` events bump the score. `scan` is descriptive (operator
    knows Defender engaged but didn't flag — typically the win state). The
    other RedEdr signals (network, audit-API, file ops, child processes)
    stay descriptive too, per the design decision.
    """
    rededr = dynamic_results.get('rededr', {}).get('findings', {})
    defender = rededr.get('defender_events') or []
    if not defender:
        return 0

    threat_hits = [e for e in defender if e.get('category') == 'threat']

    if threat_hits:
        # ThreatFound-class verdict at runtime is the strongest possible signal.
        risk_factors.append(
            f"Critical: Microsoft Defender flagged the binary at runtime "
            f"({len(threat_hits)} threat verdict{'s' if len(threat_hits) != 1 else ''})"
        )
        return 50
    return 0


def _calculate_memory_anomaly_risk(dynamic_results, analysis_type, risk_factors):
    moneta_findings = dynamic_results.get('moneta', {}).get('findings', {})
    if not moneta_findings:
        return 0

    memory_scores = {
        'total_private_rwx': 15 if analysis_type == 'file' else 10,
        'total_modified_code': 12 if analysis_type == 'file' else 10,
        'total_heap_executable': 10,
        'total_modified_pe_header': 10,
        'total_private_rx': 8,
        'total_inconsistent_x': 8,
        'total_missing_peb': 5,
        'total_mismatching_peb': 5,
    }

    total_score = 0
    anomaly_count = 0

    for key, weight in memory_scores.items():
        count = int(moneta_findings.get(key, 0) or 0)
        if count > 0:
            total_score += min(count * weight, weight * 2)
            anomaly_count += count

    if anomaly_count > 0:
        risk_factors.append(f"{anomaly_count} weighted memory anomalies observed")
        return min(total_score, 40 if analysis_type == 'file' else 30)

    return 0


def _calculate_behavior_risk(dynamic_results, analysis_type, risk_factors):
    patriot_findings = dynamic_results.get('patriot', {}).get('findings', {})
    if not patriot_findings:
        return 0

    behaviors = patriot_findings.get('findings', [])
    behavior_count = len(behaviors)

    if behavior_count == 0:
        return 0

    severity_scores = {
        'critical': 25 if analysis_type == 'file' else 20,
        'high': 15,
        'medium': 10,
        'low': 5,
    }

    behavior_score = 0
    for behavior in behaviors:
        severity = behavior.get('severity', 'low')
        behavior_score += severity_scores.get(severity, 5)

    risk_factors.append(f"{behavior_count} weighted runtime indicators observed")
    return min(behavior_score, 35)


def _calculate_hsb_risk(dynamic_results, analysis_type, risk_factors):
    hsb_findings = dynamic_results.get('hsb', {}).get('findings', {})
    if not (hsb_findings and hsb_findings.get('detections')):
        return 0

    total_hsb_score = 0
    for detection in hsb_findings['detections']:
        if not detection.get('findings'):
            continue

        count = len(detection['findings'])
        severity = detection.get('max_severity', 0)

        if analysis_type == 'file':
            severity_multiplier = 1 + (severity * 0.5)
            detection_score = min(count * 15 * severity_multiplier, 40)
        else:
            severity_scores = {0: 10, 1: 15, 2: 20}
            max_scores = {0: 20, 1: 25, 2: 35}
            detection_score = min(
                count * severity_scores.get(severity, 10),
                max_scores.get(severity, 20),
            )

        total_hsb_score += detection_score

        severity_text = ["LOW", "MID", "HIGH"][min(severity, 2)]
        if severity >= 2:
            risk_factors.append(f"Critical: {count} high-severity memory operations observed")
        else:
            risk_factors.append(f"{count} {severity_text} severity memory operations observed")

    return min(total_hsb_score, 45 if analysis_type == 'file' else 35)


def _normalize_risk_score(risk_score, analysis_type, dynamic_results, risk_factors):
    if analysis_type == 'file':
        base_score = min(max(risk_score, 0), 100)
        if base_score > 75:
            risk_score = min(base_score * 1.15, 100)
    else:
        yara_matches = dynamic_results.get('yara', {}).get('matches', []) if dynamic_results else []
        pesieve_findings = dynamic_results.get('pe_sieve', {}).get('findings', {}) if dynamic_results else {}
        pesieve_suspicious = int(pesieve_findings.get('total_suspicious', 0))

        if len(yara_matches) == 0 and pesieve_suspicious <= 1:
            risk_score = min(risk_score, 65)

        if all(f.lower().find('high') == -1 for f in risk_factors):
            risk_score = min(risk_score, 75)

    return risk_score
