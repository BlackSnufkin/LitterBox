// app/static/js/utils/index.js
// Aggregator — lets feature modules do a single import:
//   import { escapeHtml, formatBytes, apiGet, Modal } from '../utils/index.js';
// or stay explicit with per-module imports if preferred.

export { escapeHtml, html, safe } from './escape.js';
export { formatBytes, formatScanDuration, formatHex, formatTimestamp } from './formatters.js';
export { SeverityMap, normalizeSeverity, severityClasses } from './severity.js';
export { apiGet, apiPost, apiDelete, apiGetCached, clearApiCache, HttpError } from './fetch.js';
export { Modal, bindEscapeToHide } from './modals.js';
export { qs, qsa, el, replaceContent } from './dom.js';
