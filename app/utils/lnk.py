# app/utils/lnk.py
"""Windows shortcut (.lnk) analyzer.

Runs at upload time on .lnk files (alongside `get_pe_info`, `get_office_info`,
`get_html_smuggle_info`). Output lands in `file_info.lnk_info`.

Heavy lifting is in `app.analyzers.static.lnk_parser.LnkForensics`; this
module is a thin wrapper that adapts the parser to the file_io drop-in
contract (returns `{lnk_info: {...}}` ready for `file_info.update(...)`).
"""

import logging
from typing import Dict

from ..analyzers.static.lnk_parser import LnkForensics

logger = logging.getLogger(__name__)


def get_lnk_info(filepath: str) -> Dict:
    """Public entry. Returns `{lnk_info: <dict or None>}`."""
    try:
        lnk = LnkForensics(filepath)
        if not lnk.is_valid():
            return {'lnk_info': None}
        return {'lnk_info': lnk.get_forensic_data()}
    except Exception as e:
        logger.warning(f"LNK analysis failed on {filepath}: {e}")
        return {'lnk_info': None}
