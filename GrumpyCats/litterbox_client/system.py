"""System health, fleet summary, cleanup, and the parallel
`get_comprehensive_results` aggregator."""

from concurrent.futures import ThreadPoolExecutor
from typing import Dict

import requests
from urllib.parse import urljoin

from .exceptions import LitterBoxAPIError, LitterBoxError


class SystemMixin:
    # ---- health & inventory --------------------------------------------

    def check_health(self) -> Dict:
        """Lightweight liveness probe of the LitterBox service.
        Bypasses the Session's retry adapter — we want a fast yes/no,
        not a probe that retries through transient failures."""
        url = urljoin(self.base_url, "/health")
        try:
            response = requests.get(url, timeout=self.timeout, verify=self.verify_ssl)
            if response.status_code in (200, 503):  # OK and degraded both valid
                return response.json()
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Health check failed: {e}")
            return {
                "status": "error",
                "message": "Unable to connect to service",
                "details": str(e),
            }

    def get_files_summary(self) -> Dict:
        """Get summary of all analyzed files and processes."""
        response = self._make_request("GET", "/files")
        return response.json()

    def get_system_status(self) -> Dict:
        """Combined health + files-summary snapshot for `status --full`."""
        try:
            health = self.check_health()
            files_summary = self.get_files_summary()
            return {
                "health": health,
                "files_summary": files_summary,
                "status": "healthy" if health.get("status") == "ok" else "degraded",
            }
        except Exception as e:
            return {
                "health": {"status": "error", "error": str(e)},
                "files_summary": None,
                "status": "error",
            }

    def get_scanners_status(self) -> Dict:
        """Inventory of configured analyzers and whether their binaries
        exist on disk. Returns the `scanners` field of the unified /health
        response: `{rows: [...], counts: {...}}`."""
        return (self.check_health() or {}).get("scanners", {"rows": [], "counts": {}})

    # ---- destructive ---------------------------------------------------

    def cleanup(
        self,
        include_uploads: bool = True,
        include_results: bool = True,
        include_analysis: bool = True,
    ) -> Dict:
        """Wipe analysis artifacts. Destructive — confirm with the user
        before calling unless they explicitly asked."""
        data = {
            "cleanup_uploads": include_uploads,
            "cleanup_results": include_results,
            "cleanup_analysis": include_analysis,
        }
        response = self._make_request("POST", "/cleanup", json=data)
        return response.json()

    # ---- multi-fetch convenience --------------------------------------

    def get_comprehensive_results(self, target: str) -> Dict:
        """Get all available results for a target in one call.

        The five GETs are independent, so they fan out across a small
        thread pool — wall time on a populated target drops from
        sequential (~5×) to roughly the slowest single response.
        Includes EDR runs (across every profile) when present.
        """
        fetchers = [
            ("file_info",         self.get_file_info),
            ("static_results",    self.get_static_results),
            ("dynamic_results",   self.get_dynamic_results),
            ("holygrail_results", self.get_holygrail_results),
            ("edr_index",         self.get_edr_index),
        ]

        def _safe_fetch(method):
            try:
                return method(target)
            except LitterBoxAPIError as e:
                # 404 means "this analysis type wasn't run for this target",
                # which is normal and shouldn't bubble up as an error.
                return None if e.status_code == 404 else {"error": str(e)}
            except LitterBoxError as e:
                return {"error": str(e)}

        with ThreadPoolExecutor(max_workers=len(fetchers)) as executor:
            futures = {key: executor.submit(_safe_fetch, fn) for key, fn in fetchers}
            results = {key: fut.result() for key, fut in futures.items()}

        results["target"] = target
        return results
