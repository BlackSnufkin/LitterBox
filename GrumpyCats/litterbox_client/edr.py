"""EDR operations — Whiskers + Elastic Defend + Fibratus profiles.

Two split-phase analyzer flavours live behind one set of endpoints:
  * `kind: elastic`  — LitterBox queries an Elastic stack for alerts.
  * `kind: fibratus` — LitterBox polls Whiskers's event-log endpoint for
                        Fibratus rule matches (DetonatorAgent shape).

The CLI / MCP helpers don't need to care about the kind for dispatch
(`analyze_edr` works for both); they only diverge for the
`fibratus_alerts_since` test helper.
"""

import time
from typing import Dict, List, Optional

from .exceptions import LitterBoxAPIError


class EdrMixin:
    def list_edr_profiles(self) -> Dict:
        """List EDR profiles registered under Config/edr_profiles/."""
        response = self._make_request("GET", "/api/edr/profiles")
        return response.json()

    def get_edr_agents_status(self) -> Dict:
        """Latest reachability snapshot for every registered EDR profile.

        Server-side TTL-cached + pre-warmed by a background poller, so
        this is effectively instant under steady-state operation."""
        response = self._make_request("GET", "/api/edr/agents/status")
        return response.json()

    def analyze_edr(
        self,
        file_hash: str,
        profile: str,
        cmd_args: Optional[List[str]] = None,
        xor_key: Optional[int] = None,
    ) -> Dict:
        """Dispatch a payload to a registered EDR profile.

        Returns the Phase-1 result immediately (status='polling_alerts'
        on a successful exec; 'blocked_by_av' / 'agent_unreachable' /
        'busy' / 'error' otherwise). Phase-2 (alert correlation) runs in
        a server-side daemon thread; poll
        `get_edr_results(file_hash, profile)` until status is no longer
        'polling_alerts', or use `wait_for_edr_completion` below.
        """
        data: Dict = {}
        if cmd_args:
            data.update(self._validate_command_args(cmd_args))
        if xor_key is not None:
            if not 0 <= xor_key <= 255:
                raise ValueError(f"xor_key must be 0-255, got {xor_key}")
            data["xor_key"] = xor_key

        response = self._make_request(
            "POST", f"/analyze/edr/{profile}/{file_hash}", json=data,
        )
        return response.json()

    def get_edr_results(self, file_hash: str, profile: str) -> Dict:
        """Fetch the saved findings for a specific EDR profile run."""
        response = self._make_request(
            "GET", f"/api/results/edr/{profile}/{file_hash}",
        )
        return response.json()

    def get_edr_index(self, file_hash: str) -> Dict:
        """Fetch every saved EDR run for a target (one entry per profile)."""
        response = self._make_request("GET", f"/api/results/edr/{file_hash}")
        return response.json()

    def wait_for_edr_completion(
        self,
        file_hash: str,
        profile: str,
        interval: float = 3.0,
        timeout: float = 180.0,
    ) -> Dict:
        """Block until Phase-2 settles, the saved JSON appears for the
        first time, or `timeout` elapses. Returns the last-seen findings
        dict (may still be 'polling_alerts' on timeout — caller decides)."""
        deadline = time.monotonic() + timeout
        last: Optional[Dict] = None
        while time.monotonic() < deadline:
            try:
                last = self.get_edr_results(file_hash, profile)
                if (last or {}).get("status") and last.get("status") != "polling_alerts":
                    return last
            except LitterBoxAPIError as e:
                # 404 just means Phase-1 hasn't kicked off yet — keep polling.
                if e.status_code != 404:
                    raise
            time.sleep(interval)
        return last or {"status": "timeout", "error": f"Phase-2 timeout after {timeout}s"}

    def fibratus_alerts_since(
        self,
        profile: str,
        since_iso: str,
        until_iso: Optional[str] = None,
    ) -> Dict:
        """Test/debug helper: ask LitterBox to passthrough-query the
        Whiskers agent's `/api/alerts/fibratus/since` for `profile`.

        Useful right after Fibratus is installed on a new VM — you can
        verify the Fibratus → Application event log → Whiskers wire end
        to end without dispatching a payload. Returns the agent's raw
        `{supported, events: [...]}` shape; `data` strings inside each
        event are unparsed JSON the caller can deserialize.
        """
        params = {"from": since_iso}
        if until_iso:
            params["until"] = until_iso
        response = self._make_request(
            "GET", f"/api/edr/fibratus/{profile}/alerts/since", params=params,
        )
        return response.json()
