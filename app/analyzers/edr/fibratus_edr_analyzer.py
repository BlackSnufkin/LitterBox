"""End-to-end orchestrator for one Fibratus-EDR run.

Pull-from-event-log model (same shape DetonatorAgent's FibratusEdrPlugin
uses):

  * Whiskers stays a near-pure exec runner — its only Fibratus-aware bit is
    GET /api/alerts/fibratus/since which wevtutil-queries the Windows
    Application event log for `Provider=Fibratus` alert records.
  * Fibratus on the EDR VM is configured with
    `alertsenders.eventlog: {enabled: true, format: json}`. Rule matches
    land in the Application log; the kernel event stream is unaffected.
  * This analyzer: lock + exec + wait + kill + log-fetch (Phase 1), then
    polls Whiskers for new Fibratus alerts in the run's `[run_start, now]`
    window (Phase 2), filters by filename, normalizes into the same dict
    shape the saved-view renderer expects.

Per-payload flow:

  1. AgentClient.get_info -> hostname (matches what Fibratus tags onto alerts)
  2. AgentClient.lock_acquire
  3. AgentClient.exec(payload, args)  -- XOR-encoded on the wire
  4. wait for exec to exit OR exec_timeout_seconds
  5. AgentClient.kill (idempotent)
  6. AgentClient.get_execution_logs
  7. AgentClient.lock_release
  8. Phase 2: poll AgentClient.get_fibratus_alerts(run_start, now) until
     the alert count is stable for SETTLE_SECONDS or wait budget elapses.
  9. Build findings dict — same shape Elastic returns.

Shape compatibility: the alert dicts we emit follow the same keys the
ElasticEdrAnalyzer's Alert.to_dict() produces (title, severity,
detected_at, details, raw) so the existing UI renderer doesn't fork.
"""

import json as _json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import List, Optional

from app.analyzers.base import BaseAnalyzer

from .agent_client import AgentBusy, AgentClient, AgentError, AgentUnreachable
from .profile import EdrProfile


logger = logging.getLogger(__name__)


HIGH_SEVERITY = {"high", "critical"}


class FibratusEdrAnalyzer(BaseAnalyzer):
    """Per-profile Fibratus analyzer. One instance per dispatch.

    Mirrors ElasticEdrAnalyzer's split-phase API (run_exec / run_correlation)
    so registry.dispatch_split() can drive either kind through one code path.
    """

    POLL_INTERVAL_SECONDS = 2.0
    SETTLE_SECONDS = 8.0

    def __init__(self, config: dict, profile: EdrProfile):
        super().__init__(config)
        self.profile = profile
        self.agent = AgentClient(profile.agent_url)

    # ---- BaseAnalyzer ---------------------------------------------------

    def analyze(self, target):
        """Synchronous full pipeline. CLI / tests use this; the HTTP route
        uses the split-phase API instead."""
        try:
            self.results = self._run(target, executable_args=None)
        except Exception as exc:
            logger.exception("Fibratus EDR run failed")
            self.results = {
                "status": "error",
                "error": str(exc),
                "profile": self.profile.name,
            }

    def cleanup(self):
        # No long-lived resources — the agent's monitor task auto-deletes
        # the dropped payload after the spawned process exits, and the lock
        # is released inside the exec phase's finally block.
        pass

    # ---- Public split-phase API ----------------------------------------

    def run_exec(self, payload_path: str, executable_args: Optional[str] = None):
        """Phase 1. Returns (phase_1_dict, continuation)."""
        try:
            return self._run_exec_phase(payload_path, executable_args)
        except Exception as exc:
            logger.exception("Fibratus EDR Phase 1 failed")
            return {
                "status": "error",
                "error": str(exc),
                "profile": self.profile.name,
            }, None

    def run_correlation(self, continuation: dict) -> dict:
        """Phase 2. Polls Whiskers for new Fibratus alerts and returns the
        final findings dict."""
        try:
            return self._correlate_and_finalize(
                continuation["outcome"],
                continuation["agent_info"],
                continuation["hostname"],
                continuation["run_start"],
                continuation.get("file_name"),
            )
        except Exception as exc:
            logger.exception("Fibratus EDR Phase 2 failed")
            return {
                **(continuation.get("phase_1", {})),
                "status": "error",
                "error": f"alert correlation failed: {exc}",
            }

    # ---- core flow ------------------------------------------------------

    def _run(self, payload_path: str, executable_args: Optional[str]) -> dict:
        phase_1, continuation = self._run_exec_phase(payload_path, executable_args)
        if continuation is None:
            return phase_1
        return self._correlate_and_finalize(
            continuation["outcome"],
            continuation["agent_info"],
            continuation["hostname"],
            continuation["run_start"],
            continuation.get("file_name"),
        )

    def _run_exec_phase(self, payload_path: str, executable_args: Optional[str]):
        if not os.path.isfile(payload_path):
            return {
                "status": "error",
                "error": f"payload not found: {payload_path}",
                "profile": self.profile.name,
            }, None

        with open(payload_path, "rb") as f:
            file_bytes = f.read()
        filename = os.path.basename(payload_path)

        # Step 1 — discover hostname.
        try:
            info = self.agent.get_info()
        except AgentUnreachable as exc:
            return self._unreachable_result(exc), None
        except AgentError as exc:
            return {
                "status": "error",
                "error": f"agent /api/info failed: {exc}",
                "profile": self.profile.name,
            }, None

        hostname = info.get("hostname")
        if not hostname:
            return {
                "status": "error",
                "error": "agent did not report a hostname",
                "profile": self.profile.name,
                "agent_info": info,
            }, None
        logger.info(
            "Fibratus EDR run on %s (agent %s, OS %s)",
            hostname,
            info.get("agent_version"),
            info.get("os_version"),
        )

        # Step 2 — single-occupancy lock on the agent.
        try:
            self.agent.lock_acquire()
        except AgentBusy as exc:
            return {
                "status": "busy",
                "error": (
                    "the agent is currently running another payload; retry once it "
                    "finishes (or call /api/lock/release if it appears stuck)"
                ),
                "profile": self.profile.name,
                "detail": str(exc),
            }, None
        except (AgentUnreachable, AgentError) as exc:
            return {
                "status": "error",
                "error": f"lock_acquire failed: {exc}",
                "profile": self.profile.name,
            }, None

        run_start = datetime.now(timezone.utc)
        try:
            exec_outcome = self._run_locked(
                file_bytes, filename, executable_args, hostname, run_start, info
            )
        finally:
            try:
                self.agent.lock_release()
            except (AgentUnreachable, AgentError) as exc:
                logger.error("lock_release failed for profile %s: %s", self.profile.name, exc)

        if exec_outcome.get("_final"):
            terminal = dict(exec_outcome)
            terminal.pop("_final", None)
            return terminal, None

        kind = exec_outcome["kind"]
        is_blocked = (kind == "virus")
        max_wait = (
            self.profile.av_block_wait_seconds if is_blocked
            else self.profile.wait_seconds_for_alerts
        )
        exec_logs = exec_outcome.get("exec_logs", {})
        killed_by_edr = (
            False if is_blocked
            else self._classify_kill(exec_logs, filename=filename)
        )
        raw_exec_status = exec_logs.get("status")
        exec_status_label = (
            "virus" if is_blocked
            else ("killed_by_edr" if killed_by_edr else raw_exec_status)
        )
        phase_1 = {
            "status": "polling_alerts",
            "profile": self.profile.name,
            "display_name": self.profile.display_name,
            "agent_info": info,
            "hostname": hostname,
            "execution": {
                "pid": exec_outcome.get("pid"),
                "stdout": exec_logs.get("stdout", ""),
                "stderr": exec_logs.get("stderr", ""),
                "exit_code": exec_logs.get("exit_code"),
                "exec_status": exec_status_label,
                "agent_exec_status": raw_exec_status,
                "killed_by_edr": killed_by_edr,
                "message": exec_outcome.get("exec_resp", {}).get("message"),
            },
            "alerts": [],
            "summary": {
                "total_alerts": 0,
                "high_severity_alerts": 0,
                "killed_by_edr": killed_by_edr,
                "run_start": run_start.isoformat(),
                "run_end": None,
                "wait_seconds_for_alerts": max_wait,
                "blocked_by_av": is_blocked,
            },
        }
        continuation = {
            "outcome": exec_outcome,
            "agent_info": info,
            "hostname": hostname,
            "run_start": run_start,
            "phase_1": phase_1,
            "file_name": filename,
        }
        return phase_1, continuation

    def _run_locked(
        self,
        file_bytes: bytes,
        filename: str,
        executable_args: Optional[str],
        hostname: str,
        run_start: datetime,
        agent_info: dict,
    ) -> dict:
        """Agent-touching half — XOR-on-the-wire exec + wait + log fetch.
        Identical mechanics to the Elastic flow; only the surrounding
        correlation step differs."""
        xor_key = secrets.randbelow(256)
        xor_table = bytes(b ^ xor_key for b in range(256))
        xored = file_bytes.translate(xor_table)
        try:
            exec_resp = self.agent.exec(
                file_bytes=xored,
                filename=filename,
                drop_path=self.profile.drop_path,
                executable_args=executable_args,
                xor_key=xor_key,
            )
        except AgentUnreachable as exc:
            return {**self._unreachable_result(exc), "_final": True}
        except AgentError as exc:
            return {
                "status": "error",
                "error": f"exec failed: {exc}",
                "profile": self.profile.name,
                "agent_info": agent_info,
                "_final": True,
            }

        exec_status = exec_resp.get("status")
        pid = exec_resp.get("pid")

        if exec_status == "virus":
            return {
                "kind": "virus",
                "exec_resp": exec_resp,
                "exec_logs": {},
                "pid": None,
                "exec_end": datetime.now(timezone.utc),
            }

        if exec_status != "ok" or pid is None:
            return {
                "status": "error",
                "error": f"unexpected exec response: {exec_resp}",
                "profile": self.profile.name,
                "agent_info": agent_info,
                "_final": True,
            }

        self._wait_for_exit(self.profile.exec_timeout_seconds)
        exec_end = datetime.now(timezone.utc)

        try:
            self.agent.kill()
        except (AgentUnreachable, AgentError) as exc:
            logger.warning("kill request failed (non-fatal): %s", exc)

        try:
            exec_logs = self.agent.get_execution_logs()
        except (AgentUnreachable, AgentError) as exc:
            logger.warning("get_execution_logs failed: %s", exc)
            exec_logs = {}

        return {
            "kind": "exec_completed",
            "exec_resp": exec_resp,
            "exec_logs": exec_logs,
            "pid": pid,
            "exec_end": exec_end,
        }

    def _correlate_and_finalize(
        self,
        outcome: dict,
        agent_info: dict,
        hostname: str,
        run_start: datetime,
        file_name: Optional[str] = None,
    ) -> dict:
        kind = outcome["kind"]
        max_wait = (
            self.profile.av_block_wait_seconds if kind == "virus"
            else self.profile.wait_seconds_for_alerts
        )
        label = "Fibratus AV-block alert" if kind == "virus" else "Fibratus alerts"
        logger.info(
            "Polling Whiskers Fibratus event log for %s on %s (file=%s, max %ds, settle %.0fs)",
            label, hostname, file_name or "*", max_wait, self.SETTLE_SECONDS,
        )
        poll_result = self._poll_alerts(run_start, max_wait, file_name)
        alerts = poll_result["alerts"]
        run_end = poll_result["run_end"]

        if poll_result.get("error") and not alerts:
            return self._partial_result(
                poll_result["error"]["sub_status"],
                poll_result["error"]["message"],
                agent_info, outcome.get("exec_logs", {}), outcome.get("pid"),
                run_start, run_end, hostname, alerts=[],
            )

        if kind == "virus":
            return self._virus_blocked_result(
                outcome["exec_resp"], agent_info, run_start, run_end, alerts, hostname,
            )
        return self._success_result(
            agent_info, outcome["exec_logs"], outcome["pid"],
            run_start, run_end, hostname, alerts, file_name=file_name,
        )

    def _poll_alerts(
        self,
        run_start: datetime,
        max_wait_seconds: int,
        file_name: Optional[str] = None,
    ) -> dict:
        """Two-stage poll against Whiskers:
            1. Wait-for-first-hit — query GET /api/alerts/fibratus/since
               every POLL_INTERVAL_SECONDS until at least one rule match
               lands or the wait budget elapses.
            2. Settle phase — once the first hit lands, keep polling for
               SETTLE_SECONDS to catch the burst of related alerts.

        Filename narrowing happens client-side: the agent returns every
        event log record `Provider=Fibratus` in the window; we drop the
        ones whose process info doesn't reference our payload filename.

        Terminal `supported: false` (Fibratus not installed on the VM)
        short-circuits with `error` set so the caller can render a partial
        result.

        Returns `{alerts: [normalized...], run_end, error|None}`.
        """
        deadline = time.monotonic() + max_wait_seconds
        run_end = datetime.now(timezone.utc)
        latest_normalized: List[dict] = []
        settle_deadline = None
        last_seen_count = 0
        last_error = None

        while time.monotonic() < deadline:
            run_end = datetime.now(timezone.utc)
            try:
                resp = self.agent.get_fibratus_alerts(
                    run_start.isoformat(), run_end.isoformat(),
                )
                last_error = None
            except (AgentUnreachable, AgentError) as exc:
                last_error = {
                    "sub_status": "agent_error", "message": str(exc),
                }
                time.sleep(self.POLL_INTERVAL_SECONDS)
                continue

            if not resp.get("supported", True):
                # Fibratus isn't installed on this VM — terminal, no point
                # polling further. The caller turns this into a partial
                # result with a clear "Fibratus not installed" message.
                return {
                    "alerts": [],
                    "run_end": run_end,
                    "error": {
                        "sub_status": "not_supported",
                        "message": "Whiskers reports Fibratus is not installed on this VM",
                    },
                }

            raw_events = resp.get("events") or []
            latest_normalized = self._normalize_and_filter(raw_events, file_name)
            if latest_normalized:
                if settle_deadline is None:
                    settle_deadline = time.monotonic() + self.SETTLE_SECONDS
                    logger.info(
                        "First Fibratus alert(s) landed (count=%d); settling for %.0fs",
                        len(latest_normalized), self.SETTLE_SECONDS,
                    )
                elif len(latest_normalized) > last_seen_count:
                    settle_deadline = time.monotonic() + self.SETTLE_SECONDS
                last_seen_count = len(latest_normalized)
                if time.monotonic() >= settle_deadline:
                    return {"alerts": latest_normalized, "run_end": run_end, "error": None}
            time.sleep(self.POLL_INTERVAL_SECONDS)

        return {"alerts": latest_normalized, "run_end": run_end, "error": last_error}

    def _normalize_and_filter(
        self, raw_events: list, file_name: Optional[str],
    ) -> List[dict]:
        """Parse the agent's event-log records (each a dict with
        time_created / event_id / data) into renderer-shaped alert dicts,
        dropping any whose process info doesn't reference `file_name`."""
        out: List[dict] = []
        for ev in raw_events:
            if not isinstance(ev, dict):
                continue
            data_str = ev.get("data")
            if not isinstance(data_str, str):
                continue
            try:
                payload = _json.loads(data_str)
            except ValueError:
                logger.debug("Fibratus alert with non-JSON Data field; skipping")
                continue
            if not isinstance(payload, dict):
                continue
            if file_name and not _payload_mentions_filename(payload, file_name):
                continue
            entry = {
                "received_at": ev.get("time_created") or "",
                "payload": payload,
            }
            out.append(self._normalize_alert(entry))
        return out

    # ---- helpers --------------------------------------------------------

    def _wait_for_exit(self, timeout_seconds: int) -> None:
        deadline = time.monotonic() + timeout_seconds
        poll_interval = 1.0
        while time.monotonic() < deadline:
            try:
                logs = self.agent.get_execution_logs()
            except (AgentUnreachable, AgentError):
                time.sleep(poll_interval)
                continue
            status = (logs.get("status") or "").lower()
            if status and status != "running":
                return
            time.sleep(poll_interval)

    @classmethod
    def _classify_kill(
        cls,
        exec_logs: dict,
        *,
        filename: Optional[str] = None,
        alerts: Optional[list] = None,
    ) -> bool:
        """Same heuristic the Elastic analyzer uses — see the docstring
        there. For .dll payloads we require alert evidence to flag
        killed_by_edr because rundll32 exits non-zero for benign reasons."""
        raw_status = (exec_logs.get("status") or "").lower()
        if raw_status == "killed":
            return False
        exit_code = exec_logs.get("exit_code")
        if exit_code in (0, None):
            return False
        is_dll = bool(filename and filename.lower().endswith(".dll"))
        if is_dll:
            return bool(alerts)
        return True

    # ---- result builders -----------------------------------------------

    def _normalize_alert(self, entry: dict) -> dict:
        """Convert a Fibratus event-log alert into the dict shape the
        existing tools/edr.js renderer expects (title / severity /
        detected_at / details / raw).

        Real Fibratus alert JSON (alertsenders.eventlog format=json,
        Fibratus 2.4+ schema):
          {
            "id": "<uuid>",
            "title": "LSASS access from unsigned executable",
            "text": "<one-line description, populated into details.reason>",
            "description": "<long rule explanation, populated into details.rule_description>",
            "severity": "high",
            "events": [
              {
                "name": "OpenProcess", "category": "process",
                "timestamp": "2026-04-30T04:53:45.359-07:00",
                "params": {...},
                "callstack": ["addr module!symbol", ...],
                "proc": {
                    pid, ppid, name, exe, cmdline, cwd, sid, username, domain,
                    integrity_level, parent_name, parent_cmdline, ancestors[]
                }
              },
              ...
            ],
            "labels": {                    # bare keys, no mitre.* prefix
              "tactic.id": "TA0006", "tactic.name": "Credential Access",
              "technique.id": "T1003", "technique.name": "OS Credential Dumping",
              "subtechnique.id": "T1003.001", ...
            },
            "tags": [...]
          }

        Renderer's process card reads Elastic-Defend-flavored keys (name,
        pid, executable, command_line, ...). We map Fibratus's `proc` block
        accordingly. Parent process is embedded as `parent_name` /
        `parent_cmdline` keys inside the same `proc` dict (NOT a separate
        block) — we project those into a renderer-shaped parent dict.
        """
        payload = entry.get("payload") or {}
        title = payload.get("title") or "Fibratus alert"
        severity = (payload.get("severity") or "").lower() or "unknown"
        rule_id = payload.get("id")
        reason = payload.get("text")
        rule_description = payload.get("description")

        events = payload.get("events") if isinstance(payload.get("events"), list) else []
        first_event = events[0] if events else {}
        detected_at = (
            first_event.get("timestamp") if isinstance(first_event, dict) else None
        ) or entry.get("received_at")

        proc_dict = first_event.get("proc") if isinstance(first_event, dict) else None
        process = self._fibratus_proc_to_process(proc_dict)
        parent = self._fibratus_proc_to_parent(proc_dict)

        labels = payload.get("labels") if isinstance(payload.get("labels"), dict) else {}
        mitre = self._fibratus_labels_to_mitre(labels)

        rule_tags = payload.get("tags") if isinstance(payload.get("tags"), list) else []
        category = first_event.get("category") if isinstance(first_event, dict) else None
        if category and category not in rule_tags:
            rule_tags = list(rule_tags) + [category]

        details = {
            "reason": reason,
            "rule_description": rule_description,
            "rule_id": rule_id,
            "rule_tags": rule_tags,
            "process": process,
            "parent": parent,
            "mitre": mitre,
            # Keep the raw events list around for any future renderer that
            # wants to surface the full kernel-event chain (callstacks,
            # ancestors, params).
            "fibratus_events": events,
        }

        return {
            "title": title,
            "severity": severity,
            "rule_id": rule_id,
            "rule_uuid": rule_id,
            "detected_at": detected_at,
            "details": details,
            "raw": payload,
        }

    @staticmethod
    def _fibratus_proc_to_process(proc) -> Optional[dict]:
        """Map Fibratus's `events[].proc` dict to the Elastic-Defend-flavored
        keys the renderer's Process card reads."""
        if not isinstance(proc, dict):
            return None
        return {
            "name": proc.get("name"),
            "pid": proc.get("pid"),
            "executable": proc.get("exe"),
            "command_line": proc.get("cmdline"),
            "working_directory": proc.get("cwd"),
            "integrity_level": proc.get("integrity_level"),
            "entity_id": None,
        }

    @staticmethod
    def _fibratus_proc_to_parent(proc) -> Optional[dict]:
        """Fibratus embeds parent info as flat `parent_name` / `parent_cmdline`
        keys inside the child's `proc` dict (and the parent PID as `ppid`)
        rather than emitting a separate parent block. Project those into
        the renderer's Parent card shape."""
        if not isinstance(proc, dict):
            return None
        if not (proc.get("parent_name") or proc.get("parent_cmdline")):
            return None
        return {
            "name": proc.get("parent_name"),
            "pid": proc.get("ppid"),
            "executable": None,  # Fibratus doesn't ship the parent's exe path
            "command_line": proc.get("parent_cmdline"),
        }

    @staticmethod
    def _fibratus_labels_to_mitre(labels: dict) -> list:
        """Group Fibratus's flat MITRE label map into the renderer's
        per-technique chip dicts. Fibratus's actual rule pack emits BARE
        keys (no `mitre.` prefix):
            tactic.id        -> "TA0006"
            tactic.name      -> "Credential Access"
            tactic.ref       -> "https://attack.mitre.org/tactics/TA0006/"
            technique.id     -> "T1003"
            technique.name   -> "OS Credential Dumping"
            technique.ref    -> "https://attack.mitre.org/techniques/T1003/"
            subtechnique.id  -> "T1003.001"
            ...
        We also accept the older `mitre.*`-prefixed forms in case some rule
        packs ship them, since the cost of the extra fallback is one dict
        lookup. Reference URLs come straight from Fibratus when present;
        otherwise we synthesize the canonical attack.mitre.org URL.
        """
        if not isinstance(labels, dict):
            return []
        flat = {k.lower(): v for k, v in labels.items() if isinstance(v, str)}

        def _pick(*candidates):
            for c in candidates:
                v = flat.get(c)
                if v:
                    return v
            return None

        tactic_id = _pick("tactic.id", "mitre.tactic.id", "mitre.tactics.id")
        tactic_name = _pick("tactic.name", "mitre.tactic.name", "mitre.tactics.name")
        tactic_ref = _pick("tactic.ref", "tactic.reference")
        technique_id = _pick("technique.id", "mitre.technique.id", "mitre.techniques.id")
        technique_name = _pick("technique.name", "mitre.technique.name", "mitre.techniques.name")
        technique_ref = _pick("technique.ref", "technique.reference")
        sub_id = _pick("subtechnique.id", "mitre.subtechnique.id", "mitre.subtechniques.id")
        sub_name = _pick("subtechnique.name", "mitre.subtechnique.name", "mitre.subtechniques.name")
        sub_ref = _pick("subtechnique.ref", "subtechnique.reference")

        if not (tactic_id or tactic_name or technique_id or technique_name):
            return []

        chip = {
            "tactic_id": tactic_id,
            "tactic_name": tactic_name,
            "tactic_reference": (
                tactic_ref
                or (f"https://attack.mitre.org/tactics/{tactic_id}/" if tactic_id else None)
            ),
            "technique_id": technique_id,
            "technique_name": technique_name,
            "technique_reference": (
                technique_ref
                or (f"https://attack.mitre.org/techniques/{technique_id}/" if technique_id else None)
            ),
        }
        if sub_id or sub_name:
            chip["subtechnique_id"] = sub_id
            chip["subtechnique_name"] = sub_name
            chip["subtechnique_reference"] = sub_ref or (
                (lambda: (
                    f"https://attack.mitre.org/techniques/{sub_id.split('.', 1)[0]}/{sub_id.split('.', 1)[1]}/"
                ))() if sub_id and "." in sub_id else None
            )
        return [chip]

    def _success_result(
        self,
        agent_info: dict,
        exec_logs: dict,
        pid: int,
        run_start: datetime,
        run_end: datetime,
        hostname: str,
        alerts: List[dict],  # already normalized by _normalize_and_filter
        file_name: Optional[str] = None,
    ) -> dict:
        high_severity_count = sum(1 for a in alerts if a["severity"] in HIGH_SEVERITY)
        killed_by_edr = self._classify_kill(exec_logs, filename=file_name, alerts=alerts)
        raw_exec_status = exec_logs.get("status")
        exec_status_label = "killed_by_edr" if killed_by_edr else raw_exec_status

        return {
            "status": "completed",
            "profile": self.profile.name,
            "display_name": self.profile.display_name,
            "agent_info": agent_info,
            "hostname": hostname,
            "execution": {
                "pid": pid,
                "stdout": exec_logs.get("stdout", ""),
                "stderr": exec_logs.get("stderr", ""),
                "exit_code": exec_logs.get("exit_code"),
                "exec_status": exec_status_label,
                "agent_exec_status": raw_exec_status,
                "killed_by_edr": killed_by_edr,
            },
            "alerts": alerts,
            "summary": {
                "total_alerts": len(alerts),
                "high_severity_alerts": high_severity_count,
                "killed_by_edr": killed_by_edr,
                "blocked_by_av": False,
                "run_start": run_start.isoformat(),
                "run_end": run_end.isoformat(),
                "wait_seconds_for_alerts": self.profile.wait_seconds_for_alerts,
            },
        }

    def _partial_result(
        self,
        sub_status: str,
        error: str,
        agent_info: dict,
        exec_logs: dict,
        pid: Optional[int],
        run_start: datetime,
        run_end: datetime,
        hostname: str,
        alerts: List[dict],
    ) -> dict:
        """Execution succeeded but the agent / event-log query failed —
        surface what we have. Mirrors ElasticEdrAnalyzer._partial_result."""
        return {
            "status": "partial",
            "sub_status": sub_status,
            "error": error,
            "profile": self.profile.name,
            "display_name": self.profile.display_name,
            "agent_info": agent_info,
            "hostname": hostname,
            "execution": {
                "pid": pid,
                "stdout": exec_logs.get("stdout", ""),
                "stderr": exec_logs.get("stderr", ""),
                "exit_code": exec_logs.get("exit_code"),
                "exec_status": exec_logs.get("status"),
            },
            "alerts": alerts,
            "summary": {
                "total_alerts": 0,
                "high_severity_alerts": 0,
                "run_start": run_start.isoformat(),
                "run_end": run_end.isoformat(),
            },
        }

    def _virus_blocked_result(
        self,
        exec_resp: dict,
        agent_info: dict,
        run_start: datetime,
        run_end: datetime,
        alerts: List[dict],  # already normalized
        hostname: str,
    ) -> dict:
        return {
            "status": "blocked_by_av",
            "profile": self.profile.name,
            "display_name": self.profile.display_name,
            "agent_info": agent_info,
            "hostname": hostname,
            "execution": {
                "pid": None,
                "stdout": "",
                "stderr": "",
                "exit_code": None,
                "exec_status": "virus",
                "message": exec_resp.get("message"),
            },
            "alerts": alerts,
            "summary": {
                "total_alerts": len(alerts),
                "high_severity_alerts": sum(
                    1 for a in alerts if a["severity"] in HIGH_SEVERITY
                ),
                "run_start": run_start.isoformat(),
                "run_end": run_end.isoformat(),
                "wait_seconds_for_alerts": self.profile.av_block_wait_seconds,
                "blocked_by_av": True,
            },
        }

    def _unreachable_result(self, exc: Exception) -> dict:
        return {
            "status": "agent_unreachable",
            "error": str(exc),
            "profile": self.profile.name,
            "display_name": self.profile.display_name,
            "agent_url": self.profile.agent_url,
        }


def _payload_mentions_filename(payload, file_name: str) -> bool:
    """Check if `file_name` appears in any of the alert payload's
    process-related fields. Fibratus events tag every detection with
    `ps` (and `pps` for the parent), each carrying `exe`, `name`, `comm`
    (command line). Forgiving / depth-limited scan — the alert format
    isn't strictly typed across rule kinds.
    """
    if not isinstance(payload, dict):
        return False
    needle = file_name.lower()

    def _scan(obj, depth: int = 0) -> bool:
        if depth > 6:
            return False
        if isinstance(obj, str):
            return needle in obj.lower()
        if isinstance(obj, dict):
            return any(_scan(v, depth + 1) for v in obj.values())
        if isinstance(obj, list):
            return any(_scan(v, depth + 1) for v in obj)
        return False

    # Fibratus's actual schema puts process info under `events[].proc`
    # (with `parent_name`, `parent_cmdline`, `ancestors[]` flat inside).
    # We also tolerate older field names (`ps` / `pps`) as a fallback for
    # any rule pack that uses the legacy shape.
    process_blobs = []
    for key in ("events", "proc", "ps", "pps", "process"):
        v = payload.get(key)
        if v is not None:
            process_blobs.append(v)
    if process_blobs:
        return any(_scan(b) for b in process_blobs)
    return _scan(payload)
