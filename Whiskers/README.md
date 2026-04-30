# Whiskers

LitterBox's sensor agent — a single-binary HTTP execution runner. Runs on
the Windows VM where you've installed an EDR (Elastic Defend, Defender,
etc.) and accepts payloads from LitterBox over HTTP. Executes them, reports
stdout/stderr/PID/exit code back.

```
LitterBox  ── HTTP ──►  Whiskers.exe  ── Process.Spawn ──►  payload
                              │
                              └─ same VM has your EDR agent watching everything
                                 (Elastic Defend / Defender / Fibratus / etc.)
```

**Alert sourcing.** Whiskers itself does not author or interpret alerts —
they come from whatever EDR you installed alongside it. LitterBox resolves
alerts in one of two ways depending on the configured EDR profile kind:

- **`kind: elastic`** — LitterBox queries your Elastic stack directly.
  Whiskers stays a pure exec runner.
- **`kind: fibratus`** — LitterBox calls Whiskers's
  `GET /api/alerts/fibratus/since` (added v5.x), which `wevtutil`-queries
  the local Application event log for `Provider=Fibratus` rule matches.
  No remote backend needed.

The naming: in the LitterBox family, `Whiskers` is the agent — sensors
out in the field, deployed on the EDR VM, picking up what happens to a
payload during execution. The orchestrator is `LitterBox` itself; the
client library is `GrumpyCats`.

## Install

1. Get the binary
   - Download `Whiskers.exe` from the LitterBox release page, OR
   - Build from source — see [`BUILD.md`](BUILD.md)
2. Drop it anywhere on the VM (e.g. `C:\Tools\Whiskers.exe`). The folder you
   put it in becomes the agent home — payloads land in
   `<that folder>\samples\` by default and the directory is created on first
   write.
3. Allow inbound TCP 8080 in Windows Firewall:
   ```powershell
   New-NetFirewallRule -DisplayName "Whiskers" `
                       -Direction Inbound -Protocol TCP -LocalPort 8080 `
                       -Action Allow
   ```
4. Run it once to verify:
   ```powershell
   .\Whiskers.exe --port 8080
   ```
   You should see something like:
   ```
   2026-04-29T13:30:12Z  INFO  whiskers ready version=0.1.0 listen=0.0.0.0:8080
   ```
5. (Optional, recommended) Register it to auto-start on user logon so you
   don't have to launch it manually every session:
   ```powershell
   .\Whiskers.exe --install
   ```
   This creates an `ONLOGON` Windows scheduled task named `Whiskers` running
   as the current user (no UAC prompt). Log out and back in to confirm.
   To remove the task: `.\Whiskers.exe --uninstall`.

## Verify

From any machine that can reach the VM:

```bash
curl http://<edr-vm-ip>:8080/api/info
# {"hostname":"DESKTOP-...","os_version":"Windows ...","agent_version":"0.1.0",
#  "telemetry_sources":["fibratus"]}      # ← only when Fibratus is installed
```

`telemetry_sources` is auto-populated based on what's present on the VM
(currently just Fibratus presence at
`C:\Program Files\Fibratus\Bin\fibratus.exe`). The orchestrator uses this
to preflight before dispatching to a `kind: fibratus` profile.

## CLI flags

| Flag | Default | Notes |
|---|---|---|
| `--port <PORT>` | `8080` | TCP port to listen on |
| `--bind <ADDR>` | `0.0.0.0` | Bind address. Set `127.0.0.1` for loopback-only testing |
| `--max-payload-mb <MB>` | `200` | Multipart upload cap on `/api/execute/exec`. LitterBox's own upload cap is 100 MB; this leaves headroom for the multipart envelope |
| `--samples-dir <PATH>` | `<exe_dir>\samples` | Where payloads land when the orchestrator doesn't supply a per-request `drop_path`. Auto-created on first write |
| `--install` | — | Register Whiskers as an `ONLOGON` Windows scheduled task (no UAC, runs as the invoking user). Forwards any non-default flags from the current invocation into the task. Exits without starting the server |
| `--uninstall` | — | Remove the previously installed scheduled task. Exits |

The binary also accepts `--help` and `--version`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/info` | Self-reported `{hostname, os_version, agent_version, telemetry_sources}` |
| `POST` | `/api/lock/acquire` | Single-occupancy gate. 200 if free, 409 if held |
| `POST` | `/api/lock/release` | 200, idempotent |
| `GET` | `/api/lock/status` | `{in_use: bool}` |
| `POST` | `/api/execute/exec` | Multipart: `file` + `drop_path` + `executable_args` + `xor_key`. Returns `{status, pid}` immediately; the spawn runs detached. `.dll` payloads spawn via `rundll32.exe <path>,<entry> [args...]` — entry point is the first token of `executable_args`. |
| `POST` | `/api/execute/kill` | Terminate the most recent run if alive |
| `GET` | `/api/logs/execution` | `{pid, status, stdout, stderr, exit_code, started_at, finished_at, is_running}` for the most recent run |
| `GET` | `/api/logs/agent` | Plain-text agent-debug log (last 1000 lines) |
| `DELETE` | `/api/logs/agent` | Clear the agent log buffer |
| `GET` | `/api/alerts/fibratus/since` | Query params `from=<ISO8601>&until=<ISO8601>`. Returns `{supported: bool, events: [{time_created, event_id, data}]}` — `data` is the raw JSON `<Data>` from each `Provider=Fibratus` event-log record in the window. `supported: false` when Fibratus isn't installed on the VM. |

Single-occupancy by design — a new `/api/execute/exec` while a previous
run is still live will kill the previous one before starting the new
one. The lock is what the orchestrator (LitterBox) holds across the
whole exec → poll → release window to make sure two operators don't
double-fire.

The lock auto-expires after 30 minutes of being held — protects against
a crashed orchestrator stranding Whiskers.

## Security model

- Whiskers has **no authentication**. It's designed to run on a VM that
  only LitterBox should be able to reach (private network, VPN, or
  loopback). Don't expose port 8080 to the internet.
- Payloads land in `<exe_dir>\samples\` by default (override with
  `--samples-dir` or per-request via the multipart `drop_path` field).
  The drop is auto-cleaned after each run, but Whiskers never reaches
  outside the supplied path.
- Execution runs as the same user the Whiskers process is running as.
  `--install` registers the task as `ONLOGON` running as the invoking
  user — payloads run unelevated unless you launched the install from an
  elevated shell.
- The XOR option on `/api/execute/exec` keeps the payload encrypted in
  transit and during the in-memory copy on the agent — useful when your
  EDR's behavioral monitor would match a plaintext known-bad sample
  before the spawn happens.

## Troubleshooting

**`Bind error: address already in use`** — another process holds port
8080. Pick a different `--port` or stop the conflicting service.

**Curl times out from another machine** — Windows Firewall is blocking.
Verify the rule: `Get-NetFirewallRule -DisplayName "Whiskers"`.

**Lock stuck "in_use"** — wait 30 minutes for auto-expiry, or `POST
/api/lock/release` from any client (release is unauthenticated by
design — single-VM trust model).

**`/api/execute/exec` returns 500 with `Failed to spawn`** — the EDR on
the VM probably blocked the dropper or the spawn. Check your EDR's
quarantine log; this is exactly the signal we want to capture and
return to LitterBox via the alert query path.

**`/api/execute/exec` returns 200 with `{"status":"virus", ...}`** —
Whiskers detected an AV intercept on file write or spawn (Windows errno
225 / 995 / 1234). That's a successful detection from our point of view,
not a transport-level failure; the orchestrator surfaces it as
`summary.blocked_by_av: true` in the saved findings.

**`/api/logs/execution` shows empty stdout** — the spawned process may
not have flushed before exit, or it wrote to a separate console (GUI
app). For GUI / detached payloads, capture is best-effort.

**`/api/alerts/fibratus/since` returns `supported: false`** — the agent
didn't find `C:\Program Files\Fibratus\Bin\fibratus.exe` on disk. Confirm
Fibratus is installed at the default path; non-standard install paths
are not currently auto-detected.

**`/api/alerts/fibratus/since` returns prose `data` strings instead of
JSON** — Fibratus is in the default `format: pretty` mode. Edit
`%PROGRAMFILES%\Fibratus\Config\fibratus.yml` to set
`alertsenders.eventlog.format: json` and restart the Fibratus service.
