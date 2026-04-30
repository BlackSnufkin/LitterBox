"""File-management operations: upload, PID validation, delete."""

from pathlib import Path
from typing import BinaryIO, Dict, Optional, Union


class FilesMixin:
    """Upload a file (or validate / delete one)."""

    def upload_file(
        self,
        file_path: Union[str, Path, BinaryIO],
        file_name: Optional[str] = None,
    ) -> Dict:
        """Upload a file for analysis. Returns the server's `file_info`
        block including the canonical MD5 hash you'll feed into other
        endpoints.
        """
        files = self._prepare_file_upload(file_path, file_name)
        try:
            response = self._make_request("POST", "/upload", files=files)
            return response.json()
        finally:
            # If we opened the file ourselves (path-based), close it. For
            # caller-provided BinaryIO objects, the caller owns the handle.
            if isinstance(file_path, (str, Path)):
                files["file"][1].close()

    def validate_process(self, pid) -> Dict:
        """Validate that a PID exists and is accessible for dynamic analysis."""
        response = self._make_request("POST", f"/validate/{pid}")
        return response.json()

    def delete_file(self, file_hash: str) -> Dict:
        """Delete a file and all of its analysis results."""
        response = self._make_request("DELETE", f"/file/{file_hash}")
        return response.json()
