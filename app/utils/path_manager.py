# app/utils/path_manager.py
"""Filesystem lookups for analysis artifacts.

`find_file_by_hash` is hot — it's called from ~15 endpoints, often two
or three times per page load (once on the upload folder, once on the
result folder, sometimes again from a follow-up render). The naive
`os.listdir` scan it used to do was O(N) in the number of retained
samples; on a host with thousands of samples that's tens of ms
multiplied by every API request.

We back it with a per-folder hash→dirname cache that's lazily populated
on miss and revalidated against the folder's `mtime`. Adding or
removing a file in the folder bumps mtime, which makes the cache miss
on the next call and reload — no manual invalidation needed for the
common create / delete paths.
"""

import os
import threading

# Per-folder cache. Each entry: {folder_path: (mtime_ns, {hash_or_prefix: dirname})}
# Threading note: Flask is multi-threaded by default; readers and writers
# can race. A single coarse lock around mutations is plenty fast (cache
# hits don't take it).
_CACHE: dict = {}
_CACHE_LOCK = threading.Lock()


def find_file_by_hash(file_hash, search_folder):
    """Find a file or directory in `search_folder` whose name starts
    with `file_hash`. Cached against the folder's mtime.

    Returns the full path on hit, None if no entry matches or the
    folder doesn't exist.
    """
    if not file_hash:
        return None

    try:
        folder_mtime = os.stat(search_folder).st_mtime_ns
    except (FileNotFoundError, OSError):
        return None

    cache_key = os.path.abspath(search_folder)
    cached = _CACHE.get(cache_key)
    if cached is None or cached[0] != folder_mtime:
        cached = _refresh(cache_key, search_folder, folder_mtime)

    name = cached[1].get(file_hash)
    if name is None:
        # Cache miss — file may have been added since the last
        # mtime tick, or the lookup is for a hash whose entry
        # doesn't exist. Fall back to a one-off listdir scan to
        # be sure (and warm the cache while we're at it).
        cached = _refresh(cache_key, search_folder, folder_mtime, force=True)
        name = cached[1].get(file_hash)
        if name is None:
            return None
    return os.path.join(search_folder, name)


def invalidate(search_folder=None):
    """Drop the cached entry for `search_folder` (or all entries if
    None). Callers that mutate a folder out-of-band should call this so
    the next lookup re-scans. Most code paths don't need it — the
    mtime check covers common file creation / deletion."""
    with _CACHE_LOCK:
        if search_folder is None:
            _CACHE.clear()
        else:
            _CACHE.pop(os.path.abspath(search_folder), None)


def _refresh(cache_key: str, search_folder: str, mtime, force: bool = False):
    """Rebuild the index for `search_folder`. Indexes by both the full
    name and the hash-prefix portion (everything up to the first `_`)
    so callers can pass either form."""
    with _CACHE_LOCK:
        # Re-check inside the lock — another thread may have just refreshed.
        cached = _CACHE.get(cache_key)
        if not force and cached is not None and cached[0] == mtime:
            return cached
        index: dict = {}
        try:
            for entry in os.listdir(search_folder):
                # Index by full name (covers exact-match callers) AND by
                # hash prefix (covers `<md5>_<original_name>` style).
                index[entry] = entry
                prefix, _, _rest = entry.partition('_')
                if prefix and prefix not in index:
                    index[prefix] = entry
        except FileNotFoundError:
            pass
        cached = (mtime, index)
        _CACHE[cache_key] = cached
        return cached
