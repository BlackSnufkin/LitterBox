"""Python client for the LitterBox payload-analysis sandbox API.

The client class is split into per-domain mixins (files, analysis,
doppelganger, results, edr, reports, system) composed onto a small
`_BaseClient` that owns the requests Session and the generic
`_make_request` helper. Public callers import `LitterBoxClient` from
this package and treat it as one class — the split is purely an
internal organization win for maintenance.
"""

from .client import LitterBoxClient
from .exceptions import LitterBoxAPIError, LitterBoxError

__all__ = ["LitterBoxClient", "LitterBoxError", "LitterBoxAPIError"]
