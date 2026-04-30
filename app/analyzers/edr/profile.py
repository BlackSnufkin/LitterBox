"""EDR profile schema + loader.

A profile is one YAML file under `Config/edr_profiles/`. It binds a Whiskers
agent (on the EDR VM) to a backend (e.g. an Elastic stack) for alert
queries. The loader scans the directory at boot and returns a list of
validated profiles to register with the analyzer manager.

Real profile files are gitignored — the repo only ships `*.example.yml`.
"""

import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

import yaml


logger = logging.getLogger(__name__)


PROFILES_DIR = os.path.join("Config", "edr_profiles")


class EdrProfileError(ValueError):
    """Profile YAML failed validation. Message names the field at fault."""


# Recognized profile kinds.
#   `elastic`  — LitterBox queries an Elastic Defend / Detection-Engine cluster.
#   `fibratus` — LitterBox polls Whiskers's GET /api/alerts/fibratus/since,
#                which wevtutil-queries the EDR VM's Application event log
#                for `Provider=Fibratus` alert records (DetonatorAgent shape).
_PROFILE_KINDS = {"elastic", "fibratus"}


@dataclass
class EdrProfile:
    name: str
    display_name: str
    agent_url: str
    # `kind` discriminates analyzer behavior. Defaults to "elastic" so older
    # profile YAMLs (no `kind` key) keep working unchanged.
    kind: str = "elastic"

    # Elastic-only fields. Required when kind=elastic, ignored when kind=fibratus.
    elastic_url: Optional[str] = None
    elastic_apikey: Optional[str] = None
    elastic_verify_tls: bool = False

    wait_seconds_for_alerts: int = 90
    # Max polling window for the AV-block path. The orchestrator polls
    # Elastic every 2s and early-returns as soon as the prevention alert
    # is indexed. End-to-end latency is dominated by the agent's shipping
    # cadence (30s default) plus Elastic's refresh interval — 60s budget
    # covers the slow tail, but the early-return makes the typical case
    # much faster.
    av_block_wait_seconds: int = 60
    exec_timeout_seconds: int = 60
    drop_path: Optional[str] = None
    source_path: Optional[str] = field(default=None, repr=False)

    @classmethod
    def from_dict(cls, data: dict, source_path: Optional[str] = None) -> "EdrProfile":
        if not isinstance(data, dict):
            raise EdrProfileError(
                f"profile must be a YAML mapping, got {type(data).__name__}"
            )

        kind = (data.get("kind") or "elastic").strip().lower()
        if kind not in _PROFILE_KINDS:
            raise EdrProfileError(
                f"unknown profile kind {kind!r} — must be one of {sorted(_PROFILE_KINDS)}"
            )

        common_required = ("name", "display_name", "agent_url")
        if kind == "elastic":
            required = common_required + ("elastic_url", "elastic_apikey")
        else:  # fibratus — no extra fields, just the Whiskers agent URL
            required = common_required
        missing = [k for k in required if not data.get(k)]
        if missing:
            raise EdrProfileError(f"missing required field(s): {', '.join(missing)}")

        if kind == "elastic" and data["elastic_apikey"].startswith("REPLACE_ME"):
            raise EdrProfileError(
                "elastic_apikey is still the example placeholder — fill it in"
            )

        return cls(
            name=data["name"],
            display_name=data["display_name"],
            agent_url=data["agent_url"].rstrip("/"),
            kind=kind,
            elastic_url=(data.get("elastic_url") or "").rstrip("/") or None,
            elastic_apikey=data.get("elastic_apikey"),
            elastic_verify_tls=bool(data.get("elastic_verify_tls", False)),
            wait_seconds_for_alerts=int(data.get("wait_seconds_for_alerts", 90)),
            av_block_wait_seconds=int(data.get("av_block_wait_seconds", 60)),
            exec_timeout_seconds=int(data.get("exec_timeout_seconds", 60)),
            drop_path=data.get("drop_path"),
            source_path=source_path,
        )


def load_profiles(profiles_dir: str = PROFILES_DIR) -> List[EdrProfile]:
    """Scan `profiles_dir` for *.yml (excluding *.example.yml) and return a
    list of validated profiles. A malformed file is logged and skipped — one
    bad profile must not prevent the others from loading.
    """
    if not os.path.isdir(profiles_dir):
        logger.debug("EDR profiles dir %s does not exist; no profiles loaded", profiles_dir)
        return []

    profiles: List[EdrProfile] = []
    seen_names = set()

    for entry in sorted(os.listdir(profiles_dir)):
        if not entry.endswith(".yml") or entry.endswith(".example.yml"):
            continue
        path = os.path.join(profiles_dir, entry)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            profile = EdrProfile.from_dict(data, source_path=path)
        except (EdrProfileError, yaml.YAMLError, OSError) as exc:
            logger.error("skipping EDR profile %s: %s", path, exc)
            continue

        if profile.name in seen_names:
            logger.error(
                "skipping EDR profile %s: duplicate name %r (already registered)",
                path,
                profile.name,
            )
            continue
        seen_names.add(profile.name)
        profiles.append(profile)
        logger.info("loaded EDR profile %r from %s", profile.name, path)

    return profiles
