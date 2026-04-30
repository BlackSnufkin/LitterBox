"""Python client for the Whiskers HTTP agent.

Whiskers is the Rust binary deployed on the user's EDR VM. This module is a
thin wrapper around its REST API — no orchestration, no waiting, no
analysis-side logic. The orchestrators live in elastic_edr_analyzer.py
and fibratus_edr_analyzer.py.

Endpoint reference: see Whiskers/README.md.
"""

import logging
from typing import Optional

import requests


logger = logging.getLogger(__name__)


class AgentError(RuntimeError):
    """Whiskers responded but the response indicates a problem."""


class AgentUnreachable(AgentError):
    """Network-level failure: connection refused, DNS, TLS, timeout."""


class AgentBusy(AgentError):
    """Whiskers returned 409 — another run holds the lock."""


class AgentClient:
    """Thin sync wrapper over the Whiskers HTTP API.

    All methods raise AgentUnreachable for transport-level failures and
    AgentError (or AgentBusy for 409) for HTTP-level failures. The caller
    decides whether to retry, surface, or fail-soft.
    """

    def __init__(
        self,
        agent_url: str,
        timeout: float = 10.0,
        exec_timeout: float = 180.0,
        session: Optional[requests.Session] = None,
    ):
        self.agent_url = agent_url.rstrip("/")
        # `timeout` covers the cheap endpoints (info / lock / logs) where 10s
        # is plenty. `exec_timeout` is for /api/execute/exec specifically —
        # multipart upload of a 100 MB sample over a slow link plus the
        # agent's XOR-decode write can take well past 10s, so we give it a
        # much longer ceiling. 3 min is enough for any realistic payload
        # the orchestrator dispatches.
        self.timeout = timeout
        self.exec_timeout = exec_timeout
        self.session = session or requests.Session()

    # ---- info -----------------------------------------------------------

    def get_info(self) -> dict:
        """Whiskers self-reports {hostname, os_version, agent_version}.
        The hostname is what LitterBox feeds into the Elastic alert query.
        """
        return self._get("/api/info")

    # ---- lock -----------------------------------------------------------

    def lock_acquire(self) -> dict:
        """200 if free, raises AgentBusy on 409."""
        return self._post("/api/lock/acquire")

    def lock_release(self) -> dict:
        return self._post("/api/lock/release")

    def lock_status(self) -> dict:
        return self._get("/api/lock/status")

    # ---- execute --------------------------------------------------------

    def exec(
        self,
        file_bytes: bytes,
        filename: str,
        drop_path: Optional[str] = None,
        executable_args: Optional[str] = None,
        xor_key: Optional[int] = None,
    ) -> dict:
        """Send a payload over multipart and spawn it on the EDR VM.

        Returns the agent's JSON body. Common shapes:

          {"status": "ok",    "pid": <int>}              normal spawn
          {"status": "virus", "pid": null, "message": …} AV blocked write/spawn
          {"status": "error", "pid": null, "message": …} other write/spawn fail

        Whiskers returns HTTP 500 for both "virus" and "error" — for the
        "virus" case that's a quirk (the agent successfully detected the AV
        block; it's not a real server error) and we treat it as a normal
        result. The orchestrator dispatches on the parsed `status` field.

        `xor_key` is a single byte (0-255). When supplied, Whiskers applies
        it byte-by-byte as it writes the payload to disk (anti-AV-in-transit).
        Caller must XOR-encode `file_bytes` with the same key beforehand.
        """
        if xor_key is not None and not 0 <= xor_key <= 255:
            raise ValueError(f"xor_key must be a single byte 0-255, got {xor_key}")

        files = {"file": (filename, file_bytes, "application/octet-stream")}
        data: dict = {}
        if drop_path:
            data["drop_path"] = drop_path
        if executable_args:
            data["executable_args"] = executable_args
        if xor_key is not None:
            data["xor_key"] = str(xor_key)

        url = f"{self.agent_url}/api/execute/exec"
        try:
            resp = self.session.post(url, files=files, data=data, timeout=self.exec_timeout)
        except requests.RequestException as exc:
            raise AgentUnreachable(f"POST {url}: {exc}") from exc

        # Try to parse the body even on 5xx. Whiskers reports AV blocks
        # as `{"status":"virus", ...}` over HTTP 500 — that's a successful
        # detection from our point of view, not a transport-level failure.
        body = None
        try:
            body = resp.json()
        except ValueError:
            pass

        if isinstance(body, dict) and body.get("status") == "virus":
            return body

        if resp.status_code == 409:
            raise AgentBusy(f"{url} returned 409: {resp.text.strip() or 'lock held'}")
        if not resp.ok:
            raise AgentError(f"{url} returned {resp.status_code}: {resp.text.strip()}")
        return body if body is not None else {}

    def kill(self) -> dict:
        """Terminate the spawned process. Idempotent — returns success even
        if the process already exited."""
        return self._post("/api/execute/kill")

    # ---- logs -----------------------------------------------------------

    def get_execution_logs(self) -> dict:
        """Returns {pid, stdout, stderr, exit_code, status} for the last run."""
        return self._get("/api/logs/execution")

    def get_agent_logs(self) -> dict:
        """The agent's own debug log buffer (last ~1000 lines)."""
        return self._get("/api/logs/agent")

    def clear_agent_logs(self) -> dict:
        return self._delete("/api/logs/agent")

    # ---- alerts ---------------------------------------------------------

    def get_fibratus_alerts(self, since_iso: str, until_iso: str) -> dict:
        """Pull Fibratus rule-match alerts from the EDR VM's Application
        event log via Whiskers, filtered to the given UTC time window.

        Whiskers wevtutil-queries the Application log for events whose
        Provider name is `Fibratus` (Fibratus's eventlog alert sender
        writes them there when configured with `format: json`). The agent
        does no parsing — it returns the raw `<Data>` JSON strings from
        each matched event record.

        Returns a dict of shape:
            {
              "supported": bool,            # false on a non-Fibratus VM
              "events": [
                  {"time_created": "...", "event_id": int, "data": "<json>"},
                  ...
              ]
            }

        `supported: false` is a terminal state — Fibratus isn't installed
        on this VM, so the analyzer should give up and report the run as
        partial. `events: []` with `supported: true` just means no rule
        matches in the window yet (the analyzer keeps polling).
        """
        # `params=` URL-encodes properly. We can NOT inline the timestamps
        # into the URL string — `+00:00` would be parsed as a literal `+`
        # which percent-decodes to space on the server side, and Whiskers
        # rejects the malformed timestamp with HTTP 400.
        url = f"{self.agent_url}/api/alerts/fibratus/since"
        try:
            resp = self.session.get(
                url,
                params={"from": since_iso, "until": until_iso},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise AgentUnreachable(f"GET {url}: {exc}") from exc
        return self._handle(resp, url)

    # ---- internals ------------------------------------------------------

    def _get(self, path: str) -> dict:
        url = f"{self.agent_url}{path}"
        try:
            resp = self.session.get(url, timeout=self.timeout)
        except requests.RequestException as exc:
            raise AgentUnreachable(f"GET {url}: {exc}") from exc
        return self._handle(resp, url)

    def _post(self, path: str) -> dict:
        url = f"{self.agent_url}{path}"
        try:
            resp = self.session.post(url, timeout=self.timeout)
        except requests.RequestException as exc:
            raise AgentUnreachable(f"POST {url}: {exc}") from exc
        return self._handle(resp, url)

    def _delete(self, path: str) -> dict:
        url = f"{self.agent_url}{path}"
        try:
            resp = self.session.delete(url, timeout=self.timeout)
        except requests.RequestException as exc:
            raise AgentUnreachable(f"DELETE {url}: {exc}") from exc
        return self._handle(resp, url)

    @staticmethod
    def _handle(resp: requests.Response, url: str) -> dict:
        if resp.status_code == 409:
            raise AgentBusy(f"{url} returned 409: {resp.text.strip() or 'lock held'}")
        if not resp.ok:
            raise AgentError(f"{url} returned {resp.status_code}: {resp.text.strip()}")
        try:
            return resp.json()
        except ValueError:
            # Endpoints like lock/release legitimately return empty bodies on
            # success in some configurations — treat as {} rather than error.
            return {}
