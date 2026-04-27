# app/utils/__init__.py
"""Re-exports from the utils package for ergonomic imports.

Prefer importing directly from submodules in new code:
    from app.utils.risk_analyzer import calculate_risk
    from app.utils.path_manager import find_file_by_hash
"""
from .file_io import (
    FileTypeDetector,
    detect_file_type,
    get_lnk_info,
    get_office_info,
    get_pe_info,
    save_uploaded_file,
)
from .forensics import (
    RUNTIME_IMPORTS,
    SecurityAnalyzer,
    calculate_entropy,
    get_security_analyzer,
)
from .json_helpers import (
    extract_detection_counts,
    format_hex,
    format_size,
    load_json_file,
)
from .path_manager import find_file_by_hash
from .reporting import generate_html_report
from .risk_analyzer import (
    RiskCalculator,
    calculate_risk,
    calculate_yara_risk,
    get_entropy_risk_level,
    get_risk_level,
)
from .validators import allowed_file, check_tool, validate_pid

__all__ = [
    'FileTypeDetector', 'RUNTIME_IMPORTS', 'RiskCalculator', 'SecurityAnalyzer',
    'allowed_file', 'calculate_entropy', 'calculate_risk', 'calculate_yara_risk',
    'check_tool', 'detect_file_type', 'extract_detection_counts',
    'find_file_by_hash', 'format_hex', 'format_size', 'generate_html_report',
    'get_entropy_risk_level', 'get_lnk_info', 'get_office_info', 'get_pe_info',
    'get_risk_level', 'get_security_analyzer', 'load_json_file',
    'save_uploaded_file', 'validate_pid',
]
