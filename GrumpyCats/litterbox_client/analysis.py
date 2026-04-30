"""Run static / dynamic / HolyGrail analyses.

Static + dynamic both go through `analyze_file`; BYOVD analyses use the
dedicated `/holygrail` endpoint. `upload_and_analyze_driver` is a
convenience wrapper for the typical "upload .sys then run HolyGrail"
flow.
"""

from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Union

from .exceptions import LitterBoxAPIError, LitterBoxError


class AnalysisMixin:
    def analyze_file(
        self,
        target: str,
        analysis_type: str,
        cmd_args: Optional[List[str]] = None,
        wait_for_completion: bool = True,
        verify_file: bool = False,
    ) -> Dict:
        """Run analysis on a file or PID. `target` is either a file MD5
        or a numeric PID (dynamic only)."""
        self._validate_analysis_type(analysis_type, ["static", "dynamic"])

        # Pre-validate the PID for dynamic-on-pid analysis so the caller
        # gets a clean ValueError rather than a server-side 404.
        if analysis_type == "dynamic" and target.isdigit():
            try:
                self.validate_process(target)
            except LitterBoxAPIError as e:
                if e.status_code == 404:
                    raise LitterBoxError(f"Process with PID {target} not found or not accessible")
                raise
        elif analysis_type == "static" and target.isdigit():
            raise ValueError("Cannot perform static analysis on PID")

        # Optional file existence check before the (potentially expensive) analysis.
        if not target.isdigit() and verify_file:
            try:
                self.get_file_info(target)
            except LitterBoxAPIError as e:
                if e.status_code == 404:
                    raise LitterBoxError(f"File {target} not found or not yet available")

        params = {"wait": "1" if wait_for_completion else "0"}
        data = self._validate_command_args(cmd_args)

        response = self._make_request(
            "POST", f"/analyze/{analysis_type}/{target}",
            params=params, json=data,
        )

        result = response.json()
        if result.get("status") == "early_termination":
            self.logger.warning(f"Analysis terminated early: {result.get('error')}")
        elif result.get("status") == "error":
            self.logger.error(f"Analysis failed: {result.get('error')}")
        return result

    def analyze_holygrail(self, file_hash: str, wait_for_completion: bool = True) -> Dict:
        """Run HolyGrail BYOVD analysis on a kernel driver."""
        params = {"hash": file_hash}
        if wait_for_completion:
            params["wait"] = "1"
        response = self._make_request("GET", "/holygrail", params=params)
        return response.json()

    def upload_and_analyze_driver(
        self,
        file_path: Union[str, Path, BinaryIO],
        file_name: Optional[str] = None,
        run_holygrail: bool = True,
    ) -> Dict:
        """Upload a kernel driver and (by default) immediately run HolyGrail."""
        upload_result = self.upload_file(file_path, file_name)
        file_hash = upload_result["file_info"]["md5"]

        results = {"upload": upload_result, "holygrail": None}

        if run_holygrail:
            try:
                results["holygrail"] = self.analyze_holygrail(file_hash)
            except LitterBoxError as e:
                self.logger.error(f"HolyGrail analysis failed: {e}")
                results["holygrail"] = {"error": str(e)}

        return results
