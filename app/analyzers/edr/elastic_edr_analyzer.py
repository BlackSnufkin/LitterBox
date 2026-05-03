"""End-to-end orchestrator for one Elastic-EDR run.

Per-payload flow:

  1. AgentClient.get_info -> learn the EDR VM's hostname
  2. AgentClient.lock_acquire
  3. AgentClient.exec(payload, args)  -- XOR-encoded on the wire
  4. wait for exec to exit OR exec_timeout_seconds
  5. AgentClient.kill (idempotent if already exited)
  6. AgentClient.get_execution_logs -> stdout/stderr/exit_code
  7. sleep wait_seconds_for_alerts (Elastic detection rule cycle)
  8. ElasticClient.fetch_alerts(hostname_from_step_1, run_start, now)
  9. AgentClient.lock_release
 10. return findings dict

Failure model: if the agent is unreachable in step 1, mark the profile
unavailable and bail. If anything between lock_acquire and lock_release
fails, the lock is released in `finally` so the agent doesn't get stuck
in a busy state.

XOR-on-the-wire: every dispatch picks a random byte 0-255, XORs the
payload with it before multipart upload, and tells Whiskers to reverse
the XOR while writing byte-by-byte. This avoids leaving an unencrypted
copy of the payload in HTTP buffers / OS network stacks / the agent's
request memory — Defender's network inspection on the EDR VM otherwise
sees the cleartext payload before WriteAsync runs and can flag it
before our multipart parser even completes.
"""

import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import List, Optional

from app.analyzers.base import BaseAnalyzer

from .agent_client import AgentBusy, AgentClient, AgentError, AgentUnreachable
from .elastic_client import (
    Alert,
    ElasticClient,
    ElasticError,
    ElasticUnreachable,
)
from .profile import EdrProfile


logger = logging.getLogger(__name__)


# Critical-severity Elastic alerts feed the Detection Score (handled in
# risk_analyzer.py). The orchestrator just classifies; scoring is downstream.
HIGH_SEVERITY = {"high", "critical"}


class ElasticEdrAnalyzer(BaseAnalyzer):
    """Per-profile analyzer. The manager creates one of these per registered
    EdrProfile and dispatches a payload to it.

    Unlike the static / dynamic analyzers, this one takes a file PATH (the
    on-disk payload to send to the EDR VM) — never a PID. EDR analysis is
    file-only by definition: the agent owns the process lifecycle.
    """

    def __init__(self, config: dict, profile: EdrProfile):
        super().__init__(config)
        self.profile = profile
        self.agent = AgentClient(profile.agent_url)
        self.elastic = ElasticClient(
            profile.elastic_url,
            profile.elastic_apikey,
            verify_tls=profile.elastic_verify_tls,
        )

    # ---- BaseAnalyzer contract -----------------------------------------

    def analyze(self, target):
        """Synchronous full pipeline (Phase 1 + Phase 2). Used by CLI and
        tests. The HTTP route uses run_exec() + run_correlation() instead so
        the user sees Phase 1 results without waiting for Elastic polling.
        """
        try:
            self.results = self._run(target, executable_args=None)
        except Exception as exc:
            logger.exception("Elastic EDR run failed")
            self.results = {
                "status": "error",
                "error": str(exc),
                "profile": self.profile.name,
            }

    # ---- Public split-phase API ----------------------------------------

    def run_exec(self, payload_path: str, executable_args: Optional[str] = None):
        """Phase 1: dispatch + exec. Returns (phase_1_dict, continuation).

        `phase_1_dict` is what the operator sees first — it has the agent's
        identity, the spawned PID, stdout/stderr (if collected), and a
        polling-state status. It's complete on its own as a "the run
        started, here's what we know" snapshot.

        `continuation` is the state Phase 2 needs to query Elastic. It's
        None when Phase 1 produced a terminal result (agent unreachable,
        lock busy, etc.) — in that case there's nothing more to do.
        """
        try:
            return self._run_exec_phase(payload_path, executable_args)
        except Exception as exc:
            logger.exception("Elastic EDR Phase 1 failed")
            return {
                "status": "error",
                "error": str(exc),
                "profile": self.profile.name,
            }, None

    def run_correlation(self, continuation: dict) -> dict:
        """Phase 2: poll Elastic for alerts using the run window from
        Phase 1. Returns the final findings dict.
        """
        try:
            return self._correlate_and_finalize(
                continuation["outcome"],
                continuation["agent_info"],
                continuation["hostname"],
                continuation["run_start"],
                continuation.get("file_name"),
            )
        except Exception as exc:
            logger.exception("Elastic EDR Phase 2 failed")
            # Return a partial result that preserves Phase 1 data so the UI
            # still has something to show.
            return {
                **(continuation.get("phase_1", {})),
                "status": "error",
                "error": f"alert correlation failed: {exc}",
            }

    def cleanup(self):
        # No long-lived resources — the agent's monitor task auto-deletes
        # the dropped payload after the spawned process exits, and the lock
        # is released inside the exec phase's finally block.
        pass

    # ---- core flow ------------------------------------------------------

    def _run(self, payload_path: str, executable_args: Optional[str]) -> dict:
        """Synchronous full pipeline. Phase 1 then Phase 2 inline."""
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
        """Returns (phase_1_dict, continuation). Continuation is None for
        terminal failures (no point running Phase 2)."""
        if not os.path.isfile(payload_path):
            return {
                "status": "error",
                "error": f"payload not found: {payload_path}",
                "profile": self.profile.name,
            }, None

        with open(payload_path, "rb") as f:
            file_bytes = f.read()
        filename = os.path.basename(payload_path)

        # Step 1 — discover hostname from the agent itself.
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
            "Elastic EDR run on %s (agent %s, OS %s)",
            hostname,
            info.get("agent_version"),
            info.get("os_version"),
        )

        # Step 2 — acquire the single-occupancy lock.
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
        # The lock is held only for the agent-touching window (exec + wait
        # for exit + log fetch). Once that's done we release it so other
        # dispatches can start, then run Elastic correlation unlocked. The
        # query is bounded by the run's actual `[run_start, run_end]` window,
        # so a follow-up dispatch that fires its own AV-prevention alert
        # cannot pollute this run's results.
        try:
            exec_outcome = self._run_locked(
                file_bytes, filename, executable_args, hostname, run_start, info
            )
        finally:
            try:
                self.agent.lock_release()
            except (AgentUnreachable, AgentError) as exc:
                logger.error(
                    "lock_release failed for profile %s: %s",
                    self.profile.name,
                    exc,
                )

        # Short-circuit: anything that already produced a final findings
        # dict (agent-unreachable, exec error, unexpected status) is
        # terminal — no Phase 2 needed.
        if exec_outcome.get("_final"):
            terminal = dict(exec_outcome)
            terminal.pop("_final", None)
            return terminal, None

        # Build the phase-1 snapshot the UI shows immediately. It's a
        # complete EDR-result dict with status="polling_alerts" and an
        # empty alerts array; Phase 2 will overwrite it on disk when the
        # alerts arrive. The AV-block-vs-clean-exec distinction lives in
        # `summary.blocked_by_av` — we don't fork the polling status for
        # that because the polling itself happens entirely between
        # LitterBox and Elastic, regardless of what the EDR VM did.
        kind = exec_outcome["kind"]
        is_blocked = (kind == "virus")
        phase_1_status = "polling_alerts"
        max_wait = (
            self.profile.av_block_wait_seconds if is_blocked
            else self.profile.wait_seconds_for_alerts
        )
        exec_logs = exec_outcome.get("exec_logs", {})
        # For the AV-block path the process never ran, so kill
        # classification doesn't apply. For .exe successful spawns we can
        # rely on the heuristic in Phase 1; for .dll spawns the heuristic
        # produces false positives (rundll32 exits 1 on bad-export, etc.)
        # so we defer to Phase 2 which has alert evidence.
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
            "status": phase_1_status,
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
            # Filename of the dispatched payload — used by the alert query
            # to scope correlation to alerts touching THIS specific payload
            # rather than everything happening on the host during the run
            # window.
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
        """Agent-touching half of the run. Returns either:

          - a finalized dict with `_final: True` (the caller returns it as-is)
          - an "exec_outcome" dict the caller takes through the correlation
            phase (Elastic query + result building) UNLOCKED

        Keeping the lock window tight is important because malware-prevention
        alerts fire in real-time — we don't need to hold the lock through the
        post-exec wait window just to query Elastic afterwards.
        """
        # Step 3 — exec. The payload travels XOR-encoded with a random
        # per-dispatch byte; Whiskers reverses the XOR byte-by-byte while
        # writing to disk. Avoids cleartext payload sitting in HTTP buffers
        # where Defender's network inspection might flag it pre-write.
        # `bytes.translate` is C-implemented; a generator over file_bytes
        # would take seconds on a 12 MB sample.
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

        # Whiskers signals "virus" on AV-blocked write/spawn — that's a
        # legitimate end state (the AV detected the payload before it ran),
        # not an analyzer failure. We still want to query Elastic for the
        # prevention alert, but we don't need to hold the lock for that.
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

        # Step 4 — wait for exec to exit, with a timeout.
        self._wait_for_exit(self.profile.exec_timeout_seconds)
        exec_end = datetime.now(timezone.utc)

        # Step 5 — kill (idempotent; no-op if already exited).
        try:
            self.agent.kill()
        except (AgentUnreachable, AgentError) as exc:
            logger.warning("kill request failed (non-fatal): %s", exc)

        # Step 6 — pull execution logs.
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

    # Both paths poll Elastic with early-return + settle. The "settle" is
    # the short window after the first alert lands — it catches related
    # alerts that fire within a burst (a single payload often produces 2-5
    # alerts within a few seconds of each other) without forcing us to
    # wait the full max-budget when the alerts have clearly arrived.
    POLL_INTERVAL_SECONDS = 2.0
    SETTLE_SECONDS = 8.0

    def _correlate_and_finalize(
        self,
        outcome: dict,
        agent_info: dict,
        hostname: str,
        run_start: datetime,
        file_name: Optional[str] = None,
    ) -> dict:
        """Unlocked phase: poll Elastic until alerts arrive (or the wait
        budget is exhausted), let the count settle for a few seconds in
        case more alerts in the same burst are still indexing, then build
        the final findings dict.
        """
        kind = outcome["kind"]
        max_wait = (
            self.profile.av_block_wait_seconds if kind == "virus"
            else self.profile.wait_seconds_for_alerts
        )
        label = "AV-prevention alert" if kind == "virus" else "detection alerts"
        logger.info(
            "Polling Elastic for %s on %s (file=%s, max %ds, settle %.0fs)",
            label, hostname, file_name or "*", max_wait, self.SETTLE_SECONDS,
        )
        poll_result = self._poll_alerts(hostname, run_start, max_wait, file_name)

        if poll_result["error"] is not None and not poll_result["alerts"]:
            return self._partial_result(
                poll_result["error"]["sub_status"],
                poll_result["error"]["message"],
                agent_info,
                outcome["exec_logs"], outcome["pid"],
                run_start, poll_result["run_end"], hostname,
                alerts=[],
            )

        alerts = poll_result["alerts"]
        run_end = poll_result["run_end"]

        if kind == "virus":
            return self._virus_blocked_result(
                outcome["exec_resp"], agent_info, run_start, run_end, alerts
            )

        return self._success_result(
            agent_info, outcome["exec_logs"], outcome["pid"],
            run_start, run_end, hostname, alerts,
            file_name=file_name,
        )

    def _poll_alerts(
        self,
        hostname: str,
        run_start: datetime,
        max_wait_seconds: int,
        file_name: Optional[str] = None,
    ) -> dict:
        """Poll Elastic until alerts land + count stops growing, or until
        `max_wait_seconds` elapses. Returns {alerts, run_end, error}.

        Two-stage logic:
          1. Wait-for-first-hit phase — query every POLL_INTERVAL_SECONDS,
             return on the first non-empty result, OR give up after the
             max-wait budget.
          2. Settle phase (after first hit) — keep polling until the alert
             count is stable for SETTLE_SECONDS, capturing any burst of
             related alerts that arrive within a few seconds of the first.
        """
        deadline = time.monotonic() + max_wait_seconds
        latest: List[Alert] = []
        run_end = datetime.now(timezone.utc)
        last_error = None
        settle_deadline = None
        last_seen_count = 0

        while time.monotonic() < deadline:
            run_end = datetime.now(timezone.utc)
            try:
                latest = self.elastic.fetch_alerts(
                    hostname, run_start, run_end, file_name=file_name
                )
                last_error = None
            except ElasticUnreachable as exc:
                last_error = {"sub_status": "elastic_unreachable", "message": str(exc)}
            except ElasticError as exc:
                last_error = {"sub_status": "elastic_error", "message": str(exc)}

            if latest:
                if settle_deadline is None:
                    settle_deadline = time.monotonic() + self.SETTLE_SECONDS
                    logger.info(
                        "First alert(s) landed (count=%d); settling for %.0fs to catch the burst",
                        len(latest), self.SETTLE_SECONDS,
                    )
                elif len(latest) > last_seen_count:
                    # Count grew during settle — extend the window to give
                    # any further bursts the same SETTLE_SECONDS to land.
                    settle_deadline = time.monotonic() + self.SETTLE_SECONDS

                last_seen_count = len(latest)

                if time.monotonic() >= settle_deadline:
                    return {"alerts": latest, "run_end": run_end, "error": None}

            time.sleep(self.POLL_INTERVAL_SECONDS)

        return {"alerts": latest, "run_end": run_end, "error": last_error}

    # ---- helpers --------------------------------------------------------

    def _wait_for_exit(self, timeout_seconds: int) -> None:
        """Poll /api/logs/execution until status moves out of 'running' or
        the timeout fires. Returns either way — the caller will issue kill
        afterward, which is a no-op if the process already exited."""
        deadline = time.monotonic() + timeout_seconds
        poll_interval = 1.0
        while time.monotonic() < deadline:
            try:
                logs = self.agent.get_execution_logs()
            except (AgentUnreachable, AgentError):
                # Don't fail the whole run for a single transient log fetch —
                # we'll try again on the next tick or just timeout out.
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
        """Decide whether the run was killed by EDR behavior protection.

        Heuristic gate: agent didn't issue the kill AND exit_code is
        non-zero AND we have at least one Elastic alert correlating to
        the run. A non-zero exit alone is not enough — payloads crash
        for plenty of self-inflicted reasons (panic, missing dependency,
        rundll32 GetProcAddress failure, ...). Requiring alert evidence
        keeps this aligned with what the operator actually sees in the
        UI: Fibratus / Defend / etc. claims a kill only when there's
        a corresponding detection event.

        Phase 1 has no alerts yet, so this always returns False there;
        Phase 2 re-evaluates after correlation and may flip True.
        """
        raw_status = (exec_logs.get("status") or "").lower()
        if raw_status == "killed":
            # The agent issued the kill itself (orchestrator timeout).
            return False
        exit_code = exec_logs.get("exit_code")
        if exit_code in (0, None):
            return False
        return bool(alerts)

    def _success_result(
        self,
        agent_info: dict,
        exec_logs: dict,
        pid: int,
        run_start: datetime,
        run_end: datetime,
        hostname: str,
        alerts: List[Alert],
        file_name: Optional[str] = None,
    ) -> dict:
        alert_dicts = [a.to_dict() for a in alerts]
        high_severity_count = sum(1 for a in alerts if a.severity in HIGH_SEVERITY)
        # Phase 2 has alerts in hand — feed them in so the .dll-via-rundll32
        # case can confirm killed_by_edr only when alerts back it up.
        killed_by_edr = self._classify_kill(
            exec_logs, filename=file_name, alerts=alerts,
        )
        # Surface "killed_by_edr" as the user-facing exec_status when we
        # have evidence — the raw "exited" label is technically right but
        # actively misleading when behavior protection was the cause.
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
            "alerts": alert_dicts,
            "summary": {
                "total_alerts": len(alert_dicts),
                "high_severity_alerts": high_severity_count,
                "killed_by_edr": killed_by_edr,
                "blocked_by_av": False,
                "run_start": run_start.isoformat(),
                "run_end": run_end.isoformat(),
                "wait_seconds_for_alerts": self.profile.wait_seconds_for_alerts,
            },
        }

    def _virus_blocked_result(
        self,
        exec_resp: dict,
        agent_info: dict,
        run_start: datetime,
        run_end: datetime,
        alerts: List[Alert],
    ) -> dict:
        """The agent's local AV (Elastic Defend) blocked the write or spawn
        before any process ran. The correlate phase already pulled any
        prevention alerts from Elastic (the lock has been released for a
        while at this point), so we just shape the result.
        """
        alert_dicts = [a.to_dict() for a in alerts]
        return {
            "status": "blocked_by_av",
            "profile": self.profile.name,
            "display_name": self.profile.display_name,
            "agent_info": agent_info,
            "hostname": agent_info.get("hostname"),
            "execution": {
                "pid": None,
                "stdout": "",
                "stderr": "",
                "exit_code": None,
                "exec_status": "virus",
                "message": exec_resp.get("message"),
            },
            "alerts": alert_dicts,
            "summary": {
                "total_alerts": len(alert_dicts),
                "high_severity_alerts": sum(
                    1 for a in alert_dicts if a.get("severity") in HIGH_SEVERITY
                ),
                "run_start": run_start.isoformat(),
                "run_end": run_end.isoformat(),
                "wait_seconds_for_alerts": self.profile.av_block_wait_seconds,
                "blocked_by_av": True,
            },
        }

    def _partial_result(
        self,
        sub_status: str,
        error: str,
        agent_info: dict,
        exec_logs: dict,
        pid: int,
        run_start: datetime,
        run_end: datetime,
        hostname: str,
        alerts: List[Alert],
    ) -> dict:
        """Execution completed but Elastic query failed — surface what we have."""
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
            "alerts": [a.to_dict() for a in alerts],
            "summary": {
                "total_alerts": 0,
                "high_severity_alerts": 0,
                "run_start": run_start.isoformat(),
                "run_end": run_end.isoformat(),
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
