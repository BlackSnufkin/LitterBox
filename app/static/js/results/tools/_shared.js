// app/static/js/results/tools/_shared.js
// Shared rendering helpers used by every per-tool module under tools/.
//
// The .lb-* design system in app/static/css/style.css owns the visuals.
// These helpers exist so that renderers consist of small, declarative
// composition rather than long inline HTML.

import { escapeHtml } from '../../utils/escape.js';

export const ICON = {
    warn:  `<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="flex-shrink:0;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>`,
    info:  `<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="flex-shrink:0;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`,
    check: `<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="flex-shrink:0;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>`,
    error: `<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="flex-shrink:0;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`,
};

/** Red error panel for tool-level errors. */
export function errorPanel(message, details) {
    return `
        <div class="lb-empty threats" style="flex-direction: column; align-items: flex-start; padding: 14px 16px;">
            <div style="display:flex; align-items:center; gap:8px;">
                ${ICON.error}<span>${escapeHtml(message || 'Error')}</span>
            </div>
            ${details ? `<pre class="lb-mono" style="margin-top:8px; font-size:11px; color:var(--lb-text-mute); white-space:pre-wrap;">${escapeHtml(JSON.stringify(details, null, 2))}</pre>` : ''}
        </div>`;
}

/** Green empty-state for clean scans. */
export function cleanState(title, subtext) {
    return `
        <div class="lb-empty clean" style="flex-direction: column; padding: 24px 16px; gap: 6px;">
            <div style="display:flex; align-items:center; gap:8px;">
                ${ICON.check}<span class="lb-strong">${escapeHtml(title)}</span>
            </div>
            ${subtext ? `<span class="lb-muted" style="font-size:11px;">${escapeHtml(subtext)}</span>` : ''}
        </div>`;
}

/** Red empty-state for threat-detected summary banners. */
export function threatState(title, subtext) {
    return `
        <div class="lb-empty threats" style="flex-direction: column; padding: 24px 16px; gap: 6px;">
            <div style="display:flex; align-items:center; gap:8px;">
                ${ICON.warn}<span class="lb-strong">${escapeHtml(title)}</span>
            </div>
            ${subtext ? `<span class="lb-muted" style="font-size:11px;">${escapeHtml(subtext)}</span>` : ''}
        </div>`;
}

/**
 * Stat strip — one row of count chips.
 * items: [{ label, value, severity? }]   severity: clean|critical|medium|info
 */
export function statRow(items) {
    return `
        <div class="lb-chip-row" style="border: 1px solid var(--lb-border); margin-bottom: 12px;">
            ${items.map(item => {
                const isHit = item.severity === 'critical'
                    || (typeof item.value === 'number' && item.value > 0 && item.severity !== 'info' && item.severity !== 'clean');
                const color =
                    item.severity === 'clean'    ? 'color: var(--lb-sev-low);' :
                    item.severity === 'critical' ? 'color: var(--lb-accent);' :
                    item.severity === 'medium'   ? 'color: var(--lb-sev-medium);' :
                    item.severity === 'info'     ? 'color: var(--lb-text-dim);' : '';
                const longString = typeof item.value === 'string' && item.value.length > 6 ? 'font-size: 14px;' : '';
                return `
                    <div class="lb-chip${isHit ? ' hit' : ''}">
                        <div class="lb-chip-name">${escapeHtml(item.label)}</div>
                        <div class="lb-chip-count" style="${color} ${longString}">${escapeHtml(String(item.value ?? '0'))}</div>
                    </div>`;
            }).join('')}
        </div>`;
}

/** Severity badge using lb-tag classes. */
export function tag(severity, text) {
    return `<span class="lb-tag ${severity}">${escapeHtml(text)}</span>`;
}

/** Panel with a panel-header and body. */
export function panel(title, body, badge) {
    return `
        <div class="lb-panel">
            <div class="lb-panel-hdr">
                <span class="lb-glyph">▸</span>${escapeHtml(title)}
                ${badge ? `<span class="lb-panel-badge">${escapeHtml(badge)}</span>` : ''}
            </div>
            <div class="lb-panel-body">${body}</div>
        </div>`;
}

/** N-column grid of [label, value, mono?] tuples. */
export function kvGrid(pairs, cols = 2) {
    return `
        <div style="display: grid; grid-template-columns: repeat(${cols}, 1fr); gap: 10px;">
            ${pairs.map(([label, value, mono]) => `
                <div>
                    <div class="lb-eyebrow" style="margin-bottom:2px;">${escapeHtml(label)}</div>
                    <div class="${mono === false ? 'lb-strong' : 'lb-strong lb-mono'}" style="font-size: 12px; word-break: break-all;">${escapeHtml(value ?? 'N/A')}</div>
                </div>
            `).join('')}
        </div>`;
}

/** Code block with optional copy button. */
export function codeBlock(content, opts = {}) {
    const { label, copy = true, color = 'var(--lb-text-dim)' } = opts;
    const id = 'cb-' + Math.random().toString(36).slice(2, 8);
    return `
        <div style="border: 1px solid var(--lb-border); margin-top: 8px;">
            ${label ? `
                <div style="display:flex; align-items:center; justify-content:space-between; padding: 6px 10px; background: var(--lb-bg-soft); border-bottom: 1px solid var(--lb-border); font-size: 11px;">
                    <span class="lb-eyebrow">${escapeHtml(label)}</span>
                    ${copy ? `<button onclick="(function(b){const t=document.getElementById('${id}').textContent;navigator.clipboard.writeText(t);b.textContent='Copied';setTimeout(()=>b.textContent='Copy',1500);})(this)" class="lb-btn lb-btn-ghost" style="padding: 1px 8px; font-size: 10px;">Copy</button>` : ''}
                </div>` : ''}
            <pre id="${id}" class="lb-mono" style="background: var(--lb-bg); padding: 10px; font-size: 11px; color: ${color}; white-space: pre-wrap; word-break: break-all; max-height: 400px; overflow: auto; margin: 0;">${escapeHtml(content)}</pre>
        </div>`;
}

/** Build a summary scanner row (used inside #scannerResultsBody). */
export function summaryRow({ name, triggered, count, detail }) {
    return `
        <tr>
            <td>${escapeHtml(name)}</td>
            <td>${tag(triggered ? 'critical' : 'clean', triggered ? 'Detected' : 'Clean')}</td>
            <td class="lb-mono" style="color: ${triggered ? 'var(--lb-accent)' : 'var(--lb-text-mute)'};">${count}</td>
            <td class="lb-muted" style="font-size: 11px;">${escapeHtml(detail)}</td>
        </tr>`;
}

/** Re-export escapeHtml so tool modules import from one place. */
export { escapeHtml };
