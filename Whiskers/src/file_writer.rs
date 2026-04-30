//! XOR-decoding payload writer.
//!
//! Port of DetonatorAgent's `FileWriter.cs` with a chunk-sized XOR. The
//! original byte-by-byte cadence was meant to keep the unencrypted payload
//! out of a large in-memory buffer where MDE's behavioral monitoring could
//! match it. We preserve that intent with a small (64 KiB) working buffer
//! that's reused per chunk: at any instant only ≤64 KiB of cleartext lives
//! in memory, and that window is overwritten on the next iteration. The
//! kernel batches these writes, so a 12 MB sample finishes in milliseconds
//! instead of the 10+ seconds a byte-at-a-time loop took.
//!
//! NB: tokio::fs::File doesn't buffer by default and per-byte writes are
//! one syscall each — that was the perf trap.

use std::io;
use std::path::Path;

use tokio::fs::File;
use tokio::io::AsyncWriteExt;

const XOR_CHUNK: usize = 64 * 1024;

/// Write `content` to `path`. If `xor_key` is `Some`, each chunk is XOR'd
/// in a small reusable buffer before being written to disk.
pub async fn write(
    path: impl AsRef<Path>,
    content: &[u8],
    xor_key: Option<u8>,
) -> io::Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }

    let mut file = File::create(path).await?;
    match xor_key {
        Some(key) => {
            let mut buf = vec![0u8; XOR_CHUNK];
            for c in content.chunks(XOR_CHUNK) {
                let n = c.len();
                for (dst, &src) in buf[..n].iter_mut().zip(c.iter()) {
                    *dst = src ^ key;
                }
                file.write_all(&buf[..n]).await?;
                // Scrub the cleartext window before the next chunk lands —
                // belt-and-braces against any in-process memory scan.
                for b in &mut buf[..n] { *b = 0; }
            }
        }
        None => {
            file.write_all(content).await?;
        }
    }
    file.flush().await?;
    Ok(())
}
