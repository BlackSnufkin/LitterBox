// app/static/js/utils/formatters.js
// Human-readable formatting helpers — promoted from inline definitions
// scattered across results.js, summary.js, upload.js, fuzzy.js.

const SIZE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

export function formatBytes(bytes) {
    if (bytes === null || bytes === undefined) return 'N/A';
    const n = Number(bytes);
    if (!Number.isFinite(n) || n < 0) return 'N/A';
    if (n === 0) return '0 B';
    const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), SIZE_UNITS.length - 1);
    return `${(n / Math.pow(1024, i)).toFixed(2)} ${SIZE_UNITS[i]}`;
}

export function formatScanDuration(seconds) {
    const total = Number(seconds || 0);
    const minutes = Math.floor(total / 60);
    const secs = Math.floor(total % 60);
    const ms = Math.floor((total % 1) * 1000);
    return `${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}.${String(ms).padStart(3, '0')}`;
}

export function formatHex(value) {
    if (typeof value === 'string' && value.toLowerCase().startsWith('0x')) {
        return value.toLowerCase();
    }
    const n = Number(value);
    if (Number.isFinite(n)) return `0x${n.toString(16)}`;
    return String(value);
}

// Convert an ISO timestamp or epoch number to local-time string.
export function formatTimestamp(value) {
    if (value === null || value === undefined || value === '') return 'N/A';
    let date;
    if (typeof value === 'number') {
        // Heuristic: epoch in seconds vs milliseconds
        date = new Date(value < 1e12 ? value * 1000 : value);
    } else {
        date = new Date(value);
    }
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleString();
}
