"""Client for the user's self-hosted Elastic stack.

Queries the Detection Engine alerts index (`.alerts-security.alerts-*` on
Elastic 8.x — the layout the elastic-container-project deploys) for
detections raised against a specific host within a time window.

Authentication is via an Elastic API key — base64-encoded value from
Kibana's Stack Management -> API keys page. The header sent is
`Authorization: ApiKey <key>`.

This client is read-only. It never writes, deletes, or modifies anything
in the Elastic stack.
"""

import logging
from datetime import datetime
from typing import List, Optional

import requests
import urllib3


logger = logging.getLogger(__name__)


# Default index pattern. Covers Elastic 9.x stacks deployed via
# elastic-container-project, which split alerts into two indices:
#
#   .ds-logs-endpoint.alerts-default-*           Elastic Defend endpoint
#                                                alerts (real-time host
#                                                detections from the agent)
#   .internal.alerts-security.alerts-default-*   Detection Engine signals
#                                                (rules raised against
#                                                ingested events)
#
# Older clusters or different deployments can override this via the
# `elastic_index_pattern` profile field. Older patterns (legacy
# `.siem-signals-*`, the public `.alerts-security.alerts-*` alias) are
# still resolvable on most stacks if the operator points the profile at
# them explicitly.
ALERTS_INDEX_PATTERN = (
    ".ds-logs-endpoint.alerts-default-*,"
    ".internal.alerts-security.alerts-default-*"
)


class ElasticError(RuntimeError):
    """Elastic responded but the response indicates a problem."""


class ElasticUnreachable(ElasticError):
    """Network-level failure: connection refused, DNS, TLS, timeout."""


class Alert:
    """Normalized detection record. Stores the highlights the UI surfaces
    front-and-center plus a `details` dict for the rich behavior-monitor
    data (call stack, API parameters, MITRE, Defend response actions). The
    raw `_source` is preserved for anything we didn't normalize.
    """

    __slots__ = (
        "title", "severity", "rule_id", "rule_uuid", "detected_at",
        "details", "raw",
    )

    def __init__(
        self,
        title: str,
        severity: str,
        rule_id: Optional[str],
        rule_uuid: Optional[str],
        detected_at: Optional[str],
        details: dict,
        raw: dict,
    ):
        self.title = title
        self.severity = severity
        self.rule_id = rule_id
        self.rule_uuid = rule_uuid
        self.detected_at = detected_at
        self.details = details
        self.raw = raw

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "rule_uuid": self.rule_uuid,
            "detected_at": self.detected_at,
            "details": self.details,
            "raw": self.raw,
        }


class ElasticClient:
    def __init__(
        self,
        elastic_url: str,
        apikey: str,
        verify_tls: bool = False,
        timeout: float = 30.0,
        session: Optional[requests.Session] = None,
    ):
        self.elastic_url = elastic_url.rstrip("/")
        self.apikey = apikey
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"ApiKey {apikey}",
                "Content-Type": "application/json",
            }
        )

        # Operator opted out of TLS verification (typical for self-hosted
        # elastic-container-project deployments with self-signed certs).
        # Suppress urllib3's per-request InsecureRequestWarning — without
        # this it floods the log on every poll (we poll Elastic every 2s
        # while waiting for alerts to land).
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def fetch_alerts(
        self,
        hostname: str,
        start: datetime,
        end: datetime,
        size: int = 200,
        file_name: Optional[str] = None,
    ) -> List[Alert]:
        """Fetch detection alerts for `hostname` raised between `start` and
        `end` (inclusive). Returns up to `size` records, ordered by detection
        time descending.

        When `file_name` is provided, the query also requires the alert to
        reference that filename — either via `file.name` (typical for AV
        block / file-creation alerts), `file.path` (full-path match), or
        `process.executable` (when the payload actually ran and a behavior
        rule fired against it). Without this filter, host+time matches
        every alert that happened to fire during the window, which catches
        unrelated background activity on the EDR host.
        """
        if not hostname:
            raise ValueError("hostname is required to query Elastic alerts")

        # `host.name` is a keyword field — case-sensitive by default. The
        # Whiskers agent self-reports the hostname using Windows' canonical
        # casing (e.g. "DESKTOP-KJDQV7E") while ECS conventionally stores it
        # lowercase. `case_insensitive: true` (ES 7.10+) lets us match either
        # without forcing the agent or the operator to normalize.
        filters: List[dict] = [
            {"term": {"host.name": {
                "value": hostname,
                "case_insensitive": True,
            }}},
            {"range": {"@timestamp": {
                "gte": _iso(start),
                "lte": _iso(end),
            }}},
        ]

        if file_name:
            # Match alerts touching THIS specific payload across all the
            # places Elastic Defend records the filename. The MD5 prefix
            # in the filename ensures uniqueness across uploads.
            #
            # The command-line / args matches are critical for DLL
            # payloads spawned via rundll32: the running process is
            # rundll32.exe (so file.name / process.name / file.path /
            # process.executable all point at the system rundll32),
            # and the DLL's path only appears inside the command line
            # (`rundll32.exe <dll-path>,<entry>`). Same pattern for any
            # other launcher-hosted payload.
            filters.append({"bool": {
                "minimum_should_match": 1,
                "should": [
                    {"term": {"file.name": {
                        "value": file_name,
                        "case_insensitive": True,
                    }}},
                    {"term": {"process.name": {
                        "value": file_name,
                        "case_insensitive": True,
                    }}},
                    {"wildcard": {"file.path": {
                        "value": f"*{file_name}",
                        "case_insensitive": True,
                    }}},
                    {"wildcard": {"process.executable": {
                        "value": f"*{file_name}",
                        "case_insensitive": True,
                    }}},
                    {"wildcard": {"process.command_line": {
                        "value": f"*{file_name}*",
                        "case_insensitive": True,
                    }}},
                    {"wildcard": {"process.args": {
                        "value": f"*{file_name}*",
                        "case_insensitive": True,
                    }}},
                ],
            }})

        body = {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": filters}},
        }

        url = f"{self.elastic_url}/{ALERTS_INDEX_PATTERN}/_search"
        try:
            resp = self.session.post(
                url, json=body, timeout=self.timeout, verify=self.verify_tls
            )
        except requests.RequestException as exc:
            raise ElasticUnreachable(f"POST {url}: {exc}") from exc

        if not resp.ok:
            raise ElasticError(
                f"{url} returned {resp.status_code}: {resp.text.strip()[:500]}"
            )

        try:
            data = resp.json()
        except ValueError as exc:
            raise ElasticError(f"non-JSON response from {url}: {exc}") from exc

        hits = data.get("hits", {}).get("hits") or []
        return [_normalize(hit) for hit in hits]

    def ping(self) -> dict:
        """Lightweight health probe — calls `GET /` to verify the credentials
        and connectivity. Used by UI to mark the profile available/unavailable.
        """
        url = f"{self.elastic_url}/"
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=self.verify_tls)
        except requests.RequestException as exc:
            raise ElasticUnreachable(f"GET {url}: {exc}") from exc
        if not resp.ok:
            raise ElasticError(
                f"{url} returned {resp.status_code}: {resp.text.strip()[:500]}"
            )
        try:
            return resp.json()
        except ValueError:
            return {}


def _iso(dt: datetime) -> str:
    """Elasticsearch's strict_date_optional_time parser accepts ISO-8601 with
    a trailing `Z` for UTC. We normalize whatever the caller passes.
    """
    if dt.tzinfo is None:
        return dt.isoformat() + "Z"
    return dt.isoformat()


def _flat(src: dict, *keys):
    """Lookup a value across alternative key paths.

    Each key may be a dotted string. We try a flat lookup first (Elasticsearch
    often returns dotted keys verbatim — e.g. `src["kibana.alert.rule.name"]`),
    then walk it as a nested-object path (`src["kibana"]["alert"]["rule"]
    ["name"]`). The first non-None hit wins.
    """
    for key in keys:
        v = src.get(key)
        if v is not None:
            return v
        if "." in key:
            parts = key.split(".")
            cur = src
            for p in parts:
                if isinstance(cur, dict) and p in cur:
                    cur = cur[p]
                else:
                    cur = None
                    break
            if cur is not None:
                return cur
    return None


def _numeric_severity_to_label(value) -> Optional[str]:
    """Endpoint alerts report `event.severity` as a 0-100 integer. Map to
    the same low/medium/high/critical labels Kibana surfaces in its UI so
    the rest of LitterBox doesn't have to care about the schema split."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n >= 74:
        return "critical"
    if n >= 48:
        return "high"
    if n >= 22:
        return "medium"
    if n >= 0:
        return "low"
    return None


def _normalize(hit: dict) -> Alert:
    src = hit.get("_source", {}) or {}

    # Title — try every place a rule name lives, in order:
    #   - kibana.alert.rule.name  (Detection Engine signal, Elastic 8/9)
    #   - signal.rule.name        (legacy .siem-signals-*, Elastic 7)
    #   - rule.name               (endpoint behavior-protection alert)
    #   - message                 (endpoint malware-prevention alert —
    #                              file-based detections don't carry a
    #                              rule.name, just the human-readable
    #                              "Malware Prevention Alert" message)
    title = (
        _flat(src, "kibana.alert.rule.name", "signal.rule.name", "rule.name", "message")
        or "Unknown alert"
    )

    # Severity — kibana.alert.severity / signal.rule.severity are strings;
    # event.severity (endpoint alerts) is a 0-100 int and needs mapping.
    severity = _flat(src, "kibana.alert.severity", "signal.rule.severity")
    if severity is None:
        severity = _numeric_severity_to_label(_flat(src, "event.severity"))
    severity = (severity or "unknown").lower()

    rule_id = _flat(src, "kibana.alert.rule.rule_id", "signal.rule.rule_id")
    rule_uuid = _flat(
        src,
        "kibana.alert.rule.uuid",
        "signal.rule.id",
        "rule.id",   # endpoint alerts
    )
    detected_at = (
        _flat(src, "kibana.alert.original_time", "signal.original_time")
        or src.get("@timestamp")
    )

    details = _build_details(src)

    return Alert(
        title=title,
        severity=severity,
        rule_id=rule_id,
        rule_uuid=rule_uuid,
        detected_at=detected_at,
        details=details,
        raw=src,
    )


def _build_details(src: dict) -> dict:
    """Pull the structured behavior-monitor fields the UI's expandable
    detail panel needs. Returns an empty-ish dict for sparse alerts —
    the UI only renders sections that are populated.
    """
    proc = src.get("process") or {}
    proc_ext = proc.get("Ext") or {}
    thread_ext = (proc.get("thread") or {}).get("Ext") or {}

    api = proc_ext.get("api") or {}
    memory_region = proc_ext.get("memory_region") or {}
    token = proc_ext.get("token") or {}

    # File identity — populated on Defend malware-prevention alerts
    # (event.action="creation", event.code="malicious_file") where the
    # relevant subject of the alert is the file that got prevented, NOT
    # the process that wrote it. The writer process is often Whiskers
    # itself in our pipeline; surfacing it as the "subject" misleads
    # operators into thinking Whiskers got flagged when really it's
    # the payload that did. The renderer prefers `file.name` over
    # `process.name` when this block is populated.
    file_obj = src.get("file") or {}
    file_ext = file_obj.get("Ext") or {}
    malware_sig = (file_ext.get("malware_signature") or {}).get("primary") or {}
    sig_block = malware_sig.get("signature") or {}
    file_info = None
    if file_obj.get("name") or file_obj.get("path"):
        file_info = {
            "name": file_obj.get("name"),
            "path": file_obj.get("path"),
            "directory": file_obj.get("directory"),
            "size": file_obj.get("size"),
            "sha256": (file_obj.get("hash") or {}).get("sha256"),
            "code_signature": _normalize_code_signature(file_obj.get("code_signature")),
            "pe": file_obj.get("pe") or None,
            "signature_name": sig_block.get("name"),
            "signature_id": sig_block.get("id"),
        }

    # Process identity (subset that's useful to the operator).
    process_info = {
        "name": proc.get("name"),
        "executable": proc.get("executable"),
        "command_line": proc.get("command_line"),
        "pid": proc.get("pid"),
        "entity_id": proc.get("entity_id"),
        "working_directory": proc.get("working_directory"),
        "args": proc.get("args"),
        "sha256": (proc.get("hash") or {}).get("sha256"),
        "imphash": (proc.get("pe") or {}).get("imphash"),
        "code_signature": _normalize_code_signature(proc.get("code_signature")),
        "integrity_level": token.get("integrity_level_name"),
    }
    if all(v in (None, [], "") for v in process_info.values()):
        process_info = None

    # Parent process — basic identity only.
    parent = proc.get("parent") or {}
    parent_info = {
        "name": parent.get("name"),
        "executable": parent.get("executable"),
        "command_line": parent.get("command_line"),
        "pid": parent.get("pid"),
        "entity_id": parent.get("entity_id"),
    }
    if all(v in (None, "") for v in parent_info.values()):
        parent_info = None

    # API trigger — what was being called when the behavior monitor fired.
    api_info = None
    if api:
        api_info = {
            "name": api.get("name"),
            "summary": api.get("summary"),
            "behaviors": api.get("behaviors") or [],
            "metadata": api.get("metadata") or {},
        }

    # Memory region — page protection / mapped module / size for memory ops.
    memory_info = None
    if memory_region:
        memory_info = {
            "allocation_protection": memory_region.get("allocation_protection"),
            "region_protection": memory_region.get("region_protection"),
            "region_state": memory_region.get("region_state"),
            "allocation_type": memory_region.get("allocation_type"),
            "mapped_path": memory_region.get("mapped_path"),
            "allocation_size": memory_region.get("allocation_size"),
            "region_size": memory_region.get("region_size"),
            "allocation_base": memory_region.get("allocation_base"),
            "region_base": memory_region.get("region_base"),
        }

    # Call stack — list of frames. Enrich each frame with the parsed
    # module + function + offset so the UI doesn't have to re-parse.
    call_stack_raw = thread_ext.get("call_stack") or []
    call_stack = [_parse_stack_frame(f) for f in call_stack_raw if isinstance(f, dict)]
    final_module = thread_ext.get("call_stack_final_user_module") or None
    if final_module:
        final_module = {
            "name": final_module.get("name"),
            "path": final_module.get("path"),
            "sha256": (final_module.get("hash") or {}).get("sha256"),
            "code_signature": _normalize_code_signature(final_module.get("code_signature")),
            "protection_provenance": final_module.get("protection_provenance"),
            "protection_provenance_path": final_module.get("protection_provenance_path"),
            "allocation_private_bytes": final_module.get("allocation_private_bytes"),
        }

    # Defend's response actions — what was killed, isolated, etc. This is
    # the most under-appreciated chunk of an Elastic Defend alert.
    responses = []
    for r in (src.get("Responses") or []):
        if not isinstance(r, dict):
            continue
        action = r.get("action") or {}
        rp = r.get("process") or {}
        responses.append({
            "action": action.get("action"),       # e.g. "kill_process"
            "tree": bool(action.get("tree")),     # tree-kill = killed children too
            "field": action.get("field"),
            "result": r.get("result"),
            "result_message": r.get("message"),
            "target_name": rp.get("name"),
            "target_pid": rp.get("pid"),
            "target_entity_id": rp.get("entity_id"),
            "timestamp": r.get("@timestamp"),
        })

    # MITRE ATT&CK — threat[] on endpoint alerts, kibana.alert.rule.threat
    # on security signals. Same shape on both, mostly.
    mitre = []
    for t in (src.get("threat") or _flat(src, "kibana.alert.rule.threat") or []):
        if not isinstance(t, dict):
            continue
        tactic = t.get("tactic") or {}
        for tech in (t.get("technique") or []):
            if not isinstance(tech, dict):
                continue
            entry = {
                "framework": t.get("framework"),
                "tactic_id": tactic.get("id"),
                "tactic_name": tactic.get("name"),
                "tactic_reference": tactic.get("reference"),
                "technique_id": tech.get("id"),
                "technique_name": tech.get("name"),
                "technique_reference": tech.get("reference"),
            }
            subs = tech.get("subtechnique") or []
            if subs and isinstance(subs[0], dict):
                entry["subtechnique_id"] = subs[0].get("id")
                entry["subtechnique_name"] = subs[0].get("name")
                entry["subtechnique_reference"] = subs[0].get("reference")
            mitre.append(entry)

    # Rule metadata + tags (signals enrich more than endpoint alerts).
    rule_description = _flat(
        src, "kibana.alert.rule.description", "rule.description"
    )
    rule_references = (
        _flat(src, "kibana.alert.rule.references", "rule.reference") or []
    )
    if isinstance(rule_references, str):
        rule_references = [rule_references]
    rule_tags = _flat(src, "kibana.alert.rule.tags") or []

    # User identity.
    user = src.get("user") or {}
    user_info = None
    if user:
        user_info = {
            "name": user.get("name"),
            "domain": user.get("domain"),
            "id": user.get("id"),
        }

    return {
        "reason": _flat(src, "kibana.alert.reason") or src.get("message"),
        "rule_description": rule_description,
        "rule_references": list(rule_references),
        "rule_tags": list(rule_tags),
        "risk_score": _flat(src, "kibana.alert.risk_score", "event.risk_score"),
        "event_action": _flat(src, "event.action"),
        "event_category": _flat(src, "event.category"),
        "event_code": _flat(src, "event.code"),
        "event_outcome": _flat(src, "event.outcome"),
        "process": process_info,
        "parent": parent_info,
        "file": file_info,
        "api": api_info,
        "memory_region": memory_info,
        "call_stack": call_stack,
        "call_stack_summary": thread_ext.get("call_stack_summary"),
        "call_stack_final_user_module": final_module,
        "responses": responses,
        "mitre": mitre,
        "user": user_info,
    }


def _normalize_code_signature(sig) -> Optional[dict]:
    """Defend serializes code_signature inconsistently — sometimes a dict,
    sometimes a single-element list of dicts. Normalize to a dict."""
    if isinstance(sig, list):
        sig = sig[0] if sig else None
    if not isinstance(sig, dict):
        return None
    return {
        "exists": sig.get("exists"),
        "status": sig.get("status"),
        "subject_name": sig.get("subject_name"),
        "trusted": sig.get("trusted"),
    }


def _parse_stack_frame(frame: dict) -> dict:
    """Each call_stack entry has a `symbol_info` like
    `c:\\windows\\system32\\ntdll.dll!NtSetContextThread+0x14` or
    `c:\\users\\user\\desktop\\foo.exe+0xa947` or the literal string
    `Unknown`. Split it into module/function/offset so the UI can render
    the frame with proper formatting and color it by signed status.
    """
    symbol = frame.get("symbol_info") or ""
    module = function = offset = None
    if symbol and symbol != "Unknown":
        # Strip leading lowercase windows path so we just have the file.
        path_part, _, sym_part = symbol.partition("!")
        # `path_part` ends in either ".dll", ".exe", or "+0x<hex>" if
        # there's no symbol resolution.
        if "+" in path_part and not sym_part:
            base, _, off = path_part.rpartition("+")
            module = base.split("\\")[-1] or base
            offset = off
        else:
            module = path_part.split("\\")[-1] or path_part
            if sym_part:
                if "+" in sym_part:
                    function, _, offset = sym_part.rpartition("+")
                else:
                    function = sym_part
    return {
        "symbol_info": symbol or None,
        "module": module,
        "function": function,
        "offset": offset,
        "provenance": frame.get("protection_provenance"),
        "provenance_path": frame.get("protection_provenance_path"),
        "allocation_private_bytes": frame.get("allocation_private_bytes"),
        "callsite_leading_bytes": frame.get("callsite_leading_bytes"),
        "callsite_trailing_bytes": frame.get("callsite_trailing_bytes"),
    }
