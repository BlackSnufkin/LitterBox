"""Exception types raised by LitterBoxClient.

Two layers:
  * `LitterBoxError`   — base class. Thrown for transport-level failures
                         (DNS, connection refused, TLS, file-not-found
                         on upload, etc).
  * `LitterBoxAPIError` — a subclass for HTTP-error responses where
                          LitterBox itself returned a structured error.
                          Carries the parsed body and status code so
                          callers can branch on 404 / 409 / etc.
"""

from typing import Dict, Optional


class LitterBoxError(Exception):
    """Base exception for LitterBox client errors."""


class LitterBoxAPIError(LitterBoxError):
    """Exception for API-level errors (HTTP 4xx / 5xx with a parsed body)."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response: Optional[Dict] = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.response = response
