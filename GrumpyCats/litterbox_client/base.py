"""Foundation class for `LitterBoxClient` — owns the requests Session,
the generic `_make_request` helper, and shared validation utilities.

Each domain mixin (files / analysis / doppelganger / ...) inherits from
this through the final `LitterBoxClient` composition and uses
`self._make_request` plus the validation helpers without depending on
each other.
"""

import logging
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Union

import requests
from requests.adapters import HTTPAdapter, Retry
from urllib.parse import urljoin

from .exceptions import LitterBoxAPIError, LitterBoxError


class _BaseClient:
    """Session + generic HTTP helpers + shared validation primitives."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:1337",
        timeout: int = 120,
        max_retries: int = 3,
        verify_ssl: bool = True,
        logger: Optional[logging.Logger] = None,
        proxy_config: Optional[Dict] = None,
        headers: Optional[Dict] = None,
    ):
        """Initialize the LitterBox client."""
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.logger = logger or logging.getLogger(__name__)
        self.proxy_config = proxy_config
        self.headers = headers or {}
        self.session = self._create_session(max_retries)

    # ---- session lifecycle ---------------------------------------------

    def _create_session(self, max_retries: int) -> requests.Session:
        """Create and configure requests session with retries."""
        session = requests.Session()

        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        if self.proxy_config:
            session.proxies.update(self.proxy_config)
        if not self.verify_ssl:
            session.verify = False
            # Suppress SSL warnings
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        session.headers.update(self.headers)
        return session

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Close the session and cleanup resources."""
        if hasattr(self, "session"):
            self.session.close()

    # ---- HTTP --------------------------------------------------------

    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Issue one HTTP request, raise structured errors on failure.

        Wraps `requests.request` so callers get `LitterBoxAPIError` on
        HTTP 4xx/5xx (with the parsed body) and `LitterBoxError` on
        transport-level failures. Default timeout is the per-call
        `self.timeout`; callers can override with `timeout=` in kwargs.
        """
        url = urljoin(self.base_url, endpoint)
        self.logger.debug(f"Making {method} request to {url}")

        try:
            kwargs.setdefault("timeout", self.timeout)
            response = self.session.request(method, url, **kwargs)
            self.logger.debug(f"Response status: {response.status_code}")
            response.raise_for_status()
            return response

        except requests.exceptions.HTTPError:
            try:
                error_data = response.json()
            except (ValueError, AttributeError):
                error_data = {"error": response.text}

            error_msg = error_data.get("error", f"HTTP {response.status_code} error")
            raise LitterBoxAPIError(
                error_msg,
                status_code=response.status_code,
                response=error_data,
            )
        except requests.exceptions.RequestException as e:
            raise LitterBoxError(f"Request failed: {str(e)}")

    # ---- validation helpers -------------------------------------------

    def _validate_command_args(self, cmd_args: Optional[List[str]]) -> Dict:
        """Validate a list of payload command-line arguments and shape
        them into the JSON body the analysis endpoints expect."""
        if cmd_args is None:
            return {}

        if not isinstance(cmd_args, list):
            raise ValueError("Arguments must be provided as a list")

        if not all(isinstance(arg, str) for arg in cmd_args):
            raise ValueError("All arguments must be strings")

        # Block shell-meta characters that could enable command injection
        # if a downstream consumer fails to quote them properly.
        dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "{", "}"]
        for arg in cmd_args:
            if any(char in arg for char in dangerous_chars):
                raise ValueError(f"Dangerous character detected in argument: {arg}")

        return {"args": cmd_args}

    def _validate_analysis_type(self, analysis_type: str, valid_types: List[str]):
        """Validate analysis type with better error messages."""
        if analysis_type not in valid_types:
            raise ValueError(
                f"Invalid analysis_type '{analysis_type}'. "
                f"Must be one of: {', '.join(valid_types)}"
            )

    def _prepare_file_upload(
        self,
        file_path: Union[str, Path, BinaryIO],
        file_name: Optional[str] = None,
    ):
        """Prepare a multipart `file` payload from a path or file-like."""
        if isinstance(file_path, (str, Path)):
            path = Path(file_path)
            if not path.exists():
                raise LitterBoxError(f"File not found: {path}")
            if not path.is_file():
                raise LitterBoxError(f"Path is not a file: {path}")
            return {"file": (file_name or path.name, open(path, "rb"), "application/octet-stream")}

        if not file_name:
            raise ValueError("file_name is required when uploading file-like objects")
        return {"file": (file_name, file_path, "application/octet-stream")}
