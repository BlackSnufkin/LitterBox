# app/utils/path_manager.py
"""Filesystem lookups for analysis artifacts."""
import os


def find_file_by_hash(file_hash, search_folder):
    """Find a file in the specified folder whose name starts with the given hash."""
    try:
        for filename in os.listdir(search_folder):
            if filename.startswith(file_hash):
                return os.path.join(search_folder, filename)
    except FileNotFoundError:
        pass
    return None
