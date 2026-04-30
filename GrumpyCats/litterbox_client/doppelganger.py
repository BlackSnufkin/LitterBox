"""Doppelganger operations — Blender system snapshot + FuzzyHash similarity.

The single `/doppelganger` server endpoint multiplexes both engines and
the four operation kinds (`scan` / `compare` / `analyze` / `create_db`).
We expose one unified entry point plus four convenience wrappers.
"""

from typing import Dict, List, Optional


class DoppelgangerMixin:
    def doppelganger_operation(
        self,
        analysis_type: str,
        operation: str,
        file_hash: Optional[str] = None,
        folder_path: Optional[str] = None,
        extensions: Optional[List[str]] = None,
        threshold: int = 1,
    ) -> Dict:
        """Unified Doppelganger entry point. The four convenience wrappers
        below cover the operations that actually have CLI shape."""
        self._validate_doppelganger_params(analysis_type, operation, file_hash, folder_path)

        # Comparison reads use GET so they're cheap to retry.
        if file_hash and operation in ["compare", "analyze"]:
            params = {"type": analysis_type, "hash": file_hash}
            if operation == "analyze" and analysis_type == "fuzzy":
                params["threshold"] = threshold
            response = self._make_request("GET", "/doppelganger", params=params)
            return response.json()

        # Mutating ops (scan / create_db / analyze with extra args) go via POST.
        data = {"type": analysis_type, "operation": operation}

        if operation == "create_db":
            data["folder_path"] = folder_path
            if extensions:
                data["extensions"] = extensions
        elif operation == "analyze":
            data["hash"] = file_hash
            data["threshold"] = threshold

        response = self._make_request("POST", "/doppelganger", json=data)
        return response.json()

    def run_blender_scan(self) -> Dict:
        """Run a system-wide Blender host snapshot."""
        return self.doppelganger_operation("blender", "scan")

    def compare_with_blender(self, file_hash: str) -> Dict:
        """Compare a file against the latest Blender host snapshot."""
        return self.doppelganger_operation("blender", "compare", file_hash=file_hash)

    def create_fuzzy_database(
        self, folder_path: str, extensions: Optional[List[str]] = None,
    ) -> Dict:
        """(Re)build the FuzzyHash baseline DB from a folder of references."""
        return self.doppelganger_operation(
            "fuzzy", "create_db", folder_path=folder_path, extensions=extensions,
        )

    def analyze_with_fuzzy(self, file_hash: str, threshold: int = 1) -> Dict:
        """Score a payload's similarity to the baseline via fuzzy hashing."""
        return self.doppelganger_operation(
            "fuzzy", "analyze", file_hash=file_hash, threshold=threshold,
        )

    # ---- internal --------------------------------------------------------

    @staticmethod
    def _validate_doppelganger_params(
        analysis_type: str,
        operation: str,
        file_hash: Optional[str],
        folder_path: Optional[str],
    ):
        if analysis_type not in ["blender", "fuzzy"]:
            raise ValueError("analysis_type must be either 'blender' or 'fuzzy'")
        if operation == "scan" and analysis_type != "blender":
            raise ValueError("scan operation is only available for blender analysis")
        if operation == "create_db" and not folder_path:
            raise ValueError("folder_path is required for create_db operation")
        if operation == "analyze" and not file_hash:
            raise ValueError("file_hash is required for analyze operation")
