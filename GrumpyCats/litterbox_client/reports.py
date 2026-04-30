"""Report retrieval — inline HTML, save-to-disk, open-in-browser."""

import os
import re
import tempfile
import webbrowser
from datetime import datetime
from typing import Optional, Union

import requests

from .exceptions import LitterBoxError


class ReportsMixin:
    def get_report(self, target: str, download: bool = False) -> Union[str, bytes]:
        """Fetch the analysis report. Returns the HTML string by default,
        or raw bytes when `download=True` (useful for piping)."""
        params = {"download": "true" if download else "false"}
        response = self._make_request("GET", f"/api/report/{target}", params=params)
        return response.content if download else response.text

    def download_report(self, target: str, output_path: Optional[str] = None) -> str:
        """Download the report and save to disk. Returns the path written.

        Streams chunks to disk so multi-MB reports don't sit in memory.
        """
        response = self._make_request(
            "GET", f"/api/report/{target}",
            params={"download": "true"}, stream=True,
        )

        filename = self._extract_filename_from_response(response, target)

        # If `output_path` is a directory, save inside it; else use it as-is.
        if output_path:
            save_path = (
                os.path.join(output_path, filename)
                if os.path.isdir(output_path)
                else output_path
            )
        else:
            save_path = filename

        try:
            with open(save_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:  # filter out keep-alive chunks
                        f.write(chunk)
            self.logger.info(f"Report saved to {save_path}")
            return save_path
        except Exception as e:
            raise LitterBoxError(f"Failed to save report: {str(e)}")

    def open_report_in_browser(self, target: str) -> bool:
        """Render the report and open it in the default browser via a
        temp file. Returns False on any failure (logged)."""
        try:
            report_content = self.get_report(target, download=False)

            fd, path = tempfile.mkstemp(suffix=".html", prefix="litterbox_report_")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                    tmp.write(report_content)
                webbrowser.open("file://" + path)
                self.logger.info(f"Report opened in browser from {path}")
                return True
            except Exception as e:
                self.logger.error(f"Failed to open report in browser: {str(e)}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to generate report: {str(e)}")
            return False

    # ---- internal -------------------------------------------------------

    @staticmethod
    def _extract_filename_from_response(response: requests.Response, target: str) -> str:
        """Pull the filename from the Content-Disposition header, or
        synthesize one with a timestamp for fallback."""
        content_disposition = response.headers.get("Content-Disposition", "")
        if "filename=" in content_disposition:
            match = re.search(r'filename="([^"]+)"', content_disposition)
            if match:
                return match.group(1)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"LitterBox_Report_{target[:8]}_{timestamp}.html"
