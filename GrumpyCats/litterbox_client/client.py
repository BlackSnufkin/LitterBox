"""Final `LitterBoxClient` — composes the per-domain mixins onto
`_BaseClient`. Public callers import this name from `litterbox_client`
(re-exported in __init__) and treat it as a single class.
"""

from .analysis import AnalysisMixin
from .base import _BaseClient
from .doppelganger import DoppelgangerMixin
from .edr import EdrMixin
from .files import FilesMixin
from .reports import ReportsMixin
from .results import ResultsMixin
from .system import SystemMixin


class LitterBoxClient(
    FilesMixin,
    AnalysisMixin,
    DoppelgangerMixin,
    ResultsMixin,
    EdrMixin,
    ReportsMixin,
    SystemMixin,
    _BaseClient,
):
    """Python client for the LitterBox payload-analysis sandbox API.

    The class itself is a thin composition: each domain (files,
    analysis, doppelganger, results, EDR, reports, system) lives in its
    own mixin module under `litterbox_client/`, and they all share the
    `_BaseClient`'s requests Session + `_make_request` helpers.

    Usage stays the same as the pre-split single-file client:

        with LitterBoxClient("http://localhost:1337") as c:
            result = c.upload_file("malware.exe")
            ...
    """
