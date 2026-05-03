# Whiskers

LitterBox's sensor agent — a single-binary Rust HTTP execution runner. Runs on the Windows VM where you've installed an EDR (Elastic Defend, Fibratus, Defender, etc.) and accepts payloads from LitterBox over HTTP. Executes them, reports stdout/stderr/PID/exit code back, and (for `kind: fibratus` profiles) `wevtutil`-queries the local Application event log on demand.

```
LitterBox  ── HTTP ──►  Whiskers.exe  ── Process.Spawn ──►  payload
                              │
                              └─ same VM has your EDR agent watching everything
                                 (Elastic Defend / Fibratus / Defender / etc.)
```

In the LitterBox family: `LitterBox` is the orchestrator, `GrumpyCats` is the client library, and **`Whiskers`** is the agent — sensors out in the field, picking up what happens to a payload during execution.

## Documentation

Full agent docs (install, CLI flags, endpoints, security model, troubleshooting) live in the wiki: **[Whiskers Agent](../../../wiki/Whiskers-Agent)**.

For end-to-end setup walkthroughs combining Whiskers with each EDR backend:
- **[Elastic Defend Setup](../../../wiki/Elastic-Defend-Setup)** — `kind: elastic` profiles
- **[Fibratus Setup](../../../wiki/Fibratus-Setup)** — `kind: fibratus` profiles

## Quick verify

From any machine that can reach the VM:

```bash
curl http://<edr-vm-ip>:8080/api/info
# {"hostname":"DESKTOP-...","os_version":"Windows ...","agent_version":"0.1.0",
#  "telemetry_sources":["fibratus"]}      # ← only when Fibratus is installed
```

## Building from source

Whiskers is a single Rust binary. Two supported build paths.

### On Windows (native)

```powershell
# Toolchain — install once via rustup-init.exe from https://rustup.rs
rustup target add x86_64-pc-windows-msvc

# Build
cargo build --release

# Result
target\release\Whiskers.exe        # ~1.6 MB, no runtime deps
```

The binary is fully static (no MSVCRT runtime DLL chase) when built with `x86_64-pc-windows-msvc` — the MSVC linker bundles vcruntime statically by default on `cargo build --release`.

### On Linux (cross-compile to Windows x64)

For CI / Linux dev hosts. Uses the mingw-w64 GCC cross-toolchain.

```bash
# One-time toolchain setup (Debian / Ubuntu / Kali)
sudo apt install gcc-mingw-w64-x86-64
rustup target add x86_64-pc-windows-gnu

# Build
cargo build --release --target x86_64-pc-windows-gnu

# Result
target/x86_64-pc-windows-gnu/release/Whiskers.exe
```

If the linker complains about missing CRT, add to `~/.cargo/config.toml` once:

```toml
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
```

The MSVC and GNU outputs are functionally equivalent; MSVC's binary is slightly smaller (better LTO with `panic = "abort"`), GNU's ships from any Linux box without a Windows machine in the loop.

### Release profile

`Cargo.toml` already configures the release profile for size:

```toml
[profile.release]
opt-level = "z"      # optimize for size
lto = true           # link-time optimization
codegen-units = 1    # better optimization at the cost of compile time
strip = true         # strip symbols
panic = "abort"      # smaller binary, no unwinding tables
```

Strip + panic=abort + LTO together cut roughly 60% off the unoptimized `cargo build` size.

### Verifying a local build

```bash
# Smoke test
./target/release/Whiskers.exe --port 8087 --bind 127.0.0.1 &
AGENT_PID=$!
sleep 1
curl -s http://127.0.0.1:8087/api/info
kill $AGENT_PID

# Unit tests (parser-critical pieces — wevtutil XML + ISO timestamps)
cargo test --release
```

For the full integration test scenario (lock / exec / kill / logs + fibratus alerts round-trip), drop the binary on a real EDR VM and exercise it from LitterBox via `grumpycat.py edr-status` and `grumpycat.py fibratus-alerts --profile <name>`.
