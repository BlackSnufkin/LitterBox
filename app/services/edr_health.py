"""Cached EDR-profile reachability probe.

The dashboard renders one card per profile and shows agent + backend
reachability. Probing every profile on every page load makes the
dashboard slow — especially when one of the targets is offline and
we wait the full timeout. This module fixes that with two layers:

  1. A short TTL cache keyed by registered-profiles set. Repeat reads
     within the TTL window return the cached snapshot instantly.

  2. A background daemon thread that pre-warms the cache every
     `REFRESH_INTERVAL` seconds, so even the first dashboard load
     after app boot lands on a warm cache (after ~one initial probe
     cycle).

The endpoint in app/blueprints/api.py reads `get_status_snapshot()`,
which serves the cache or triggers a synchronous probe on cold start.
"""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional


logger = logging.getLogger(__name__)


# Per-call timeouts. Tighter than the previous defaults (agent=4s,
# elastic=5s): when a service is reachable it answers in milliseconds,
# so 2s is plenty of grace; when it's unreachable we fail fast and the
# poller's next cycle picks up recovery within REFRESH_INTERVAL.
AGENT_TIMEOUT_S = 2.0
ELASTIC_TIMEOUT_S = 2.0

# How long a cached snapshot is considered fresh. Background poller
# refreshes more often than this, so reads under healthy operation
# always hit a fresh cache.
CACHE_TTL_S = 30.0

# Background poller cadence. Faster than CACHE_TTL_S so the cache is
# perpetually warm; slower than the dashboard's auto-refresh (60s) so
# we don't probe more than necessary.
REFRESH_INTERVAL_S = 15.0


_lock = threading.Lock()
_cached: Optional[dict] = None
_cached_at: float = 0.0
_poller_started = False


def get_status_snapshot(profiles: List, *, force_refresh: bool = False) -> dict:
    """Return the latest agent-status snapshot.

    Cached for `CACHE_TTL_S` seconds against the current registered-
    profiles tuple. Cold reads (no cache, or expired) trigger a
    synchronous probe; warm reads return the cache instantly.
    """
    global _cached, _cached_at

    if not profiles:
        return {"agents": [], "cache_age_seconds": 0}

    profile_key = _profile_key(profiles)

    with _lock:
        cached = _cached
        cached_at = _cached_at
        cache_valid = (
            cached is not None
            and not force_refresh
            and (time.monotonic() - cached_at) < CACHE_TTL_S
            and cached.get("_profile_key") == profile_key
        )

    if cache_valid:
        age = time.monotonic() - cached_at
        return _public_snapshot(cached, age)

    snapshot = _probe_all(profiles)
    snapshot["_profile_key"] = profile_key
    with _lock:
        _cached = snapshot
        _cached_at = time.monotonic()
    return _public_snapshot(snapshot, 0.0)


def start_poller(deps) -> None:
    """Kick off the background pre-warming thread. Idempotent — second
    call is a no-op so reload-aware test setups can't spawn duplicates.
    `deps` is the litterbox extension namespace; we pull profiles off
    `deps.edr_registry._PROFILES` on each tick so YAML-edit-then-restart
    flows pick up new profiles automatically (a restart re-creates deps,
    which re-runs start_poller)."""
    global _poller_started
    with _lock:
        if _poller_started:
            return
        _poller_started = True

    def _loop():
        # Initial delay so app startup isn't gated on probe latency.
        time.sleep(0.5)
        while True:
            try:
                profiles = list(deps.edr_registry._PROFILES.values())
                if profiles:
                    get_status_snapshot(profiles, force_refresh=True)
            except Exception:
                logger.exception("EDR health poller tick failed")
            time.sleep(REFRESH_INTERVAL_S)

    t = threading.Thread(target=_loop, name="edr-health-poller", daemon=True)
    t.start()
    logger.info("EDR health poller started (interval=%ss)", REFRESH_INTERVAL_S)


# ---- internals ---------------------------------------------------------


def _profile_key(profiles: List) -> tuple:
    """Stable key for the cache so a profile add/remove forces a refresh
    rather than serving stale entries."""
    return tuple(sorted((p.name, p.kind, p.agent_url) for p in profiles))


def _public_snapshot(snapshot: dict, age: float) -> dict:
    """Strip internal cache-bookkeeping and stamp `cache_age_seconds`."""
    out = {k: v for k, v in snapshot.items() if not k.startswith("_")}
    out["cache_age_seconds"] = round(age, 1)
    return out


def _probe_all(profiles: List) -> dict:
    """Probe every profile in parallel. Wall time is dominated by the
    slowest single probe (per-probe timeout is bounded above)."""
    with ThreadPoolExecutor(max_workers=min(8, len(profiles))) as pool:
        results = list(pool.map(_probe_one, profiles))
    return {"agents": results}


def _probe_one(p) -> dict:
    """One profile's reachability check. Lazy-imports the EDR clients
    to keep top-level import cost off the request hot path on cold
    boots that don't touch this module."""
    from ..analyzers.edr.agent_client import AgentClient, AgentError, AgentUnreachable
    from ..analyzers.edr.elastic_client import ElasticClient, ElasticError, ElasticUnreachable

    agent = AgentClient(p.agent_url, timeout=AGENT_TIMEOUT_S)
    agent_info, agent_err, lock = None, None, None
    try:
        agent_info = agent.get_info()
        try:
            lock = agent.lock_status()
        except (AgentUnreachable, AgentError):
            pass
    except AgentUnreachable as e:
        agent_err = f"unreachable: {e}"
    except AgentError as e:
        agent_err = f"error: {e}"

    elastic_info, elastic_err = None, None
    type_label = "elastic-defend"
    if p.kind == "elastic":
        elastic = ElasticClient(
            p.elastic_url, p.elastic_apikey,
            verify_tls=p.elastic_verify_tls, timeout=ELASTIC_TIMEOUT_S,
        )
        try:
            elastic_info = elastic.ping()
        except ElasticUnreachable as e:
            elastic_err = f"unreachable: {e}"
        except ElasticError as e:
            elastic_err = f"error: {e}"
    elif p.kind == "fibratus":
        type_label = "fibratus"

    return {
        "name": p.name,
        "display_name": p.display_name,
        "type": type_label,
        "kind": p.kind,
        "agent_url": p.agent_url,
        "elastic_url": p.elastic_url,
        "agent": {
            "reachable": agent_info is not None,
            "error": agent_err,
            "hostname": (agent_info or {}).get("hostname"),
            "os_version": (agent_info or {}).get("os_version"),
            "agent_version": (agent_info or {}).get("agent_version"),
            "telemetry_sources": (agent_info or {}).get("telemetry_sources") or [],
        },
        "lock": lock,
        "elastic": {
            "reachable": elastic_info is not None if p.kind == "elastic" else None,
            "error": elastic_err,
            "cluster_name": (elastic_info or {}).get("cluster_name"),
            "version": ((elastic_info or {}).get("version") or {}).get("number"),
        },
    }
