"""Profile registry — single entry point for EDR-profile dispatch.

The Flask blueprints layer calls into this module rather than reaching into
profile.py / elastic_edr_analyzer.py directly. Three responsibilities:

  1. Load profiles at import time so the UI can list them.
  2. Dispatch a payload to a named profile and return the analyzer's results
     (full synchronous run — used by tests and CLI).
  3. Dispatch in split-phase mode: Phase 1 returns immediately, Phase 2
     (Elastic correlation) runs in a background thread and invokes a
     completion callback with the final result.

The registry is a module-level singleton — profiles are loaded once when
LitterBox boots. To pick up a new YAML, restart the app (consistent with
the rest of the analyzer config).
"""

import logging
import threading
from typing import Callable, Dict, List, Optional, Tuple

from .elastic_edr_analyzer import ElasticEdrAnalyzer
from .fibratus_edr_analyzer import FibratusEdrAnalyzer
from .profile import EdrProfile, load_profiles


logger = logging.getLogger(__name__)


_PROFILES: Dict[str, EdrProfile] = {}
_LOADED = False


def _make_analyzer(profile: EdrProfile, config: dict):
    """Pick the right analyzer for a profile's `kind`. New analyzer types
    plug in here — keep this the single dispatch site."""
    if profile.kind == "fibratus":
        return FibratusEdrAnalyzer(config, profile)
    return ElasticEdrAnalyzer(config, profile)


def init(config: dict, profiles_dir: Optional[str] = None) -> None:
    """Load profiles from disk. Called once at app startup. Idempotent —
    re-calling reloads the registry, which is useful for tests but
    intentionally not exposed via HTTP (profile YAML edits require a
    restart, same as config.yaml).
    """
    global _LOADED, _PROFILES
    profiles = load_profiles(profiles_dir) if profiles_dir else load_profiles()
    _PROFILES = {p.name: p for p in profiles}
    _LOADED = True
    logger.info(
        "EDR registry initialized with %d profile(s): %s",
        len(_PROFILES),
        list(_PROFILES.keys()),
    )


def list_profiles() -> List[dict]:
    """Public-facing profile list for the UI. Intentionally omits secrets
    (apikey, ingest_token) — only the operator-facing identity + agent URL
    is returned. `kind` is included so the UI can render kind-specific
    affordances when needed.
    """
    return [
        {
            "name": p.name,
            "display_name": p.display_name,
            "agent_url": p.agent_url,
            "elastic_url": p.elastic_url,
            "kind": p.kind,
        }
        for p in _PROFILES.values()
    ]


def get_profile(name: str) -> Optional[EdrProfile]:
    return _PROFILES.get(name)


def dispatch(profile_name: str, payload_path: str, config: dict) -> dict:
    """Run one payload against `profile_name`. Returns the analyzer's
    findings dict (see elastic_edr_analyzer for the schema). Raises
    KeyError if the profile is not registered — callers should validate
    against list_profiles() first.

    Synchronous: blocks until BOTH Phase 1 (exec) and Phase 2 (Elastic
    correlation) finish. Used by tests/CLI. The HTTP route uses
    dispatch_split() so the user sees Phase 1 results immediately.
    """
    profile = _PROFILES.get(profile_name)
    if profile is None:
        raise KeyError(f"unknown EDR profile: {profile_name!r}")

    analyzer = _make_analyzer(profile, config)
    analyzer.analyze(payload_path)
    try:
        return analyzer.get_results()
    finally:
        analyzer.cleanup()


def dispatch_split(
    profile_name: str,
    payload_path: str,
    config: dict,
    on_phase_2_done: Callable[[dict], None],
    executable_args: Optional[str] = None,
) -> dict:
    """Split-phase dispatch.

    Phase 1 (lock + exec + log fetch) runs synchronously and the result is
    returned immediately. If Phase 1 was non-terminal (the run actually
    started or was AV-blocked), Phase 2 (poll Elastic for alerts) is
    spawned in a background thread; when it completes, `on_phase_2_done`
    is called with the final findings dict. The callback is responsible
    for persisting the updated result.

    `executable_args` is forwarded to the agent's exec endpoint as a
    single space-separated string. For DLL payloads the first token is
    the exported entry point (rundll32 wraps it server-side).

    Phase 2 errors are swallowed and surfaced to the callback as a
    `status: 'error'` dict — the thread never raises into nothing.
    """
    profile = _PROFILES.get(profile_name)
    if profile is None:
        raise KeyError(f"unknown EDR profile: {profile_name!r}")

    analyzer = _make_analyzer(profile, config)
    phase_1, continuation = analyzer.run_exec(payload_path, executable_args)

    if continuation is None:
        # Terminal failure (busy, agent unreachable, missing file, etc.) —
        # no Phase 2 to schedule. Caller still saves Phase 1 as the final
        # result.
        analyzer.cleanup()
        return phase_1

    def _phase_2_runner():
        try:
            phase_2 = analyzer.run_correlation(continuation)
        except Exception as exc:
            logger.exception("EDR Phase 2 thread crashed")
            phase_2 = {
                **phase_1,
                "status": "error",
                "error": f"Phase 2 thread crashed: {exc}",
            }
        finally:
            analyzer.cleanup()
        try:
            on_phase_2_done(phase_2)
        except Exception:
            logger.exception("on_phase_2_done callback raised")

    thread = threading.Thread(
        target=_phase_2_runner,
        name=f"edr-phase2-{profile_name}",
        daemon=True,
    )
    thread.start()
    return phase_1


def is_loaded() -> bool:
    return _LOADED
