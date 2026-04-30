# Build pipeline — Whiskers

Whiskers is a single Rust binary. Two supported build paths.

## On Windows (native)

```powershell
# Toolchain — install once via rustup-init.exe from https://rustup.rs
rustup target add x86_64-pc-windows-msvc

# Build
cargo build --release

# Result
target\release\Whiskers.exe        # ~1 MB, no runtime deps
```

The binary is fully static (no MSVCRT runtime DLL chase) when built with
`x86_64-pc-windows-msvc` — the MSVC linker bundles vcruntime statically by
default on `cargo build --release`.

## On Linux (cross-compile to Windows x64)

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

If linker complains about missing CRT, add to `~/.cargo/config.toml` once:

```toml
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
```

The MSVC and GNU outputs are functionally equivalent; MSVC's binary is
slightly smaller (better LTO with our `panic = "abort"` config), GNU's
ships from any Linux box without a Windows machine in the loop.

## Release profile

`Cargo.toml` already configures the release profile for size:

```toml
[profile.release]
opt-level = "z"      # optimize for size
lto = true           # link-time optimization
codegen-units = 1    # better optimization at the cost of compile time
strip = true         # strip symbols
panic = "abort"      # smaller binary, no unwinding tables
```

Result is ~1 MB. Strip + panic=abort + LTO together cut roughly 60% off
the unoptimized `cargo build` size.

## Verifying a build

```bash
# Quick smoke test
./target/release/Whiskers.exe --port 8087 --bind 127.0.0.1 &
AGENT_PID=$!
sleep 1
curl -s http://127.0.0.1:8087/api/info
# Expected: {"hostname":"...","os_version":"...","agent_version":"0.1.0",
#            "telemetry_sources": [...]}
kill $AGENT_PID
```

The unit tests cover the parser-critical pieces — wevtutil XML parsing
(both single- and double-quoted attribute styles) and ISO timestamp
formatting. Run with:

```bash
cargo test --release
```

For the full integration test scenario (lock / exec / kill / logs +
fibratus alerts round-trip), drop the binary on a real EDR VM and exercise
it from LitterBox via `grumpycat.py edr-status` and
`grumpycat.py fibratus-alerts --profile <name>`.
