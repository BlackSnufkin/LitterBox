//! XOR-decoding payload writer.
//!
//! Port of DetonatorAgent's `FileWriter.cs`: streams bytes one-at-a-time
//! through an XOR transform as it writes to disk. The byte-by-byte cadence
//! is deliberate — keeps the unencrypted payload from sitting in a single
//! large buffer in agent memory, where MDE's behavioral monitoring could
//! match it before the spawn happens.

use std::io;
use std::path::Path;

use tokio::fs::File;
use tokio::io::AsyncWriteExt;

/// Write `content` to `path`. If `xor_key` is `Some`, each byte is XOR'd
/// with the key before write — single-byte writes, no intermediate buffer.
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
            let mut buf = [0u8; 1];
            for &b in content {
                buf[0] = b ^ key;
                file.write_all(&buf).await?;
            }
        }
        None => {
            file.write_all(content).await?;
        }
    }
    file.flush().await?;
    Ok(())
}
