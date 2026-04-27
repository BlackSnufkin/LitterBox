# app/utils/validators.py
"""Input validation helpers — file extensions, PIDs, tool availability."""
import os
from functools import lru_cache

import psutil


@lru_cache(maxsize=128)
def _allowed_file_cached(filename, allowed_extensions_tuple):
    return ('.' in filename and
            filename.rsplit('.', 1)[1].lower() in allowed_extensions_tuple)


def allowed_file(filename, allowed_extensions):
    """Check if a filename's extension is in the allowed list."""
    return _allowed_file_cached(filename, tuple(allowed_extensions))


def validate_pid(pid):
    """Validate that a PID exists and is accessible. Returns (ok, error_msg)."""
    try:
        pid = int(pid)
        if pid <= 0:
            return False, "Invalid PID: must be a positive integer"

        if not psutil.pid_exists(pid):
            return False, f"Process with PID {pid} does not exist"

        try:
            process = psutil.Process(pid)
            process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return False, f"Cannot access process {pid}: {str(e)}"

        return True, None

    except ValueError:
        return False, "Invalid PID: must be a number"
    except Exception as e:
        return False, f"Error validating PID: {str(e)}"


def check_tool(tool_path):
    """Check if a tool is accessible and executable."""
    return os.path.isfile(tool_path) and os.access(tool_path, os.X_OK)
