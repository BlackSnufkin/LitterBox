// app/static/js/results/tools/moneta.js
import { errorPanel, cleanState, statRow, panel, kvGrid, codeBlock, escapeHtml } from './_shared.js';

export default {
    id: 'moneta',
    elementId: 'monetaResults',

    render(results, ctx) {
        if (results.status === 'error') {
            ctx.element.innerHTML = errorPanel(results.error);
            return;
        }

        const f = results.findings || {};
        const suspiciousMetrics = [
            f.total_private_rx, f.total_private_rwx, f.total_modified_code,
            f.total_inconsistent_x, f.total_heap_executable, f.total_modified_pe_header,
            f.total_missing_peb, f.total_mismatching_peb, f.total_threads_non_image,
        ];
        const isClean = suspiciousMetrics.every(v => !v);

        let html = '';

        if (f.process_info) {
            html += panel('Process Information', kvGrid([
                ['Process Name', f.process_info.name],
                ['Process ID',   f.process_info.pid],
                ['Architecture', f.process_info.arch],
                ['Path',         f.process_info.path],
            ], 2), f.scan_duration ? `${f.scan_duration.toFixed(2)}s` : null);
        }

        html += statRow([
            { label: 'Status',        value: isClean ? 'Clean' : 'Detected', severity: isClean ? 'clean' : 'critical' },
            { label: 'Total Regions', value: f.total_regions || 0,             severity: 'info' },
            { label: 'Threads',       value: (f.threads || []).length,         severity: 'info' },
        ]);

        if (isClean) {
            const note = f.total_unsigned_modules > 0
                ? `Note: ${f.total_unsigned_modules} unsigned module(s) observed, but no anomalies in memory layout.`
                : 'Memory analysis completed without anomalies.';
            html += cleanState('No anomalies observed', note);
            ctx.element.innerHTML = html;
            return;
        }

        const breakdown = [
            { label: 'Private RWX',          value: f.total_private_rwx },
            { label: 'Private RX',           value: f.total_private_rx },
            { label: 'Modified Code',        value: f.total_modified_code },
            { label: 'Heap Executable',      value: f.total_heap_executable },
            { label: 'Modified PE Header',   value: f.total_modified_pe_header },
            { label: 'Inconsistent X',       value: f.total_inconsistent_x },
            { label: 'Missing PEB',          value: f.total_missing_peb },
            { label: 'Mismatching PEB',      value: f.total_mismatching_peb },
            { label: 'Unsigned Modules',     value: f.total_unsigned_modules },
            { label: 'Threads in Non-Image', value: f.total_threads_non_image },
        ];

        html += panel('Memory Anomalies', `
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;">
                ${breakdown.map(item => `
                    <div style="padding: 10px; border: 1px solid ${item.value > 0 ? 'rgba(248, 113, 113, 0.22)' : 'var(--lb-border)'};">
                        <div class="lb-eyebrow" style="margin-bottom: 4px;">${escapeHtml(item.label)}</div>
                        <div class="lb-mono lb-strong" style="font-size: 16px; color: ${item.value > 0 ? 'var(--lb-accent)' : 'var(--lb-text)'};">${item.value || 0}</div>
                    </div>
                `).join('')}
            </div>
        `);

        const warnings = [
            { cond: f.total_private_rwx > 0,        msg: `Critical: ${f.total_private_rwx} private RWX region(s) observed`,           sev: 'critical' },
            { cond: f.total_heap_executable > 0,    msg: `Critical: ${f.total_heap_executable} executable heap region(s) observed`,    sev: 'critical' },
            { cond: f.total_modified_code > 0,      msg: `Critical: ${f.total_modified_code} modified code region(s) observed`,        sev: 'critical' },
            { cond: f.total_modified_pe_header > 0, msg: `Critical: ${f.total_modified_pe_header} modified PE header(s) observed`,     sev: 'critical' },
            { cond: f.total_threads_non_image > 0,  msg: `Critical: ${f.total_threads_non_image} thread(s) in non-image memory`,       sev: 'critical' },
            { cond: f.total_private_rx > 0,         msg: `Warning: ${f.total_private_rx} private RX region(s) observed`,               sev: 'medium' },
            { cond: f.total_inconsistent_x > 0,     msg: `Warning: ${f.total_inconsistent_x} region(s) with inconsistent X perms`,     sev: 'medium' },
            { cond: f.total_missing_peb > 0,        msg: `Warning: ${f.total_missing_peb} missing PEB module(s)`,                      sev: 'medium' },
            { cond: f.total_mismatching_peb > 0,    msg: `Warning: ${f.total_mismatching_peb} mismatching PEB module(s)`,              sev: 'medium' },
        ].filter(w => w.cond);

        if (warnings.length) {
            html += panel('Triggering Indicators', `
                <ul style="list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 6px;">
                    ${warnings.map(w => `
                        <li style="display: flex; gap: 8px; padding: 6px 10px; background: var(--lb-bg); border-left: 2px solid ${w.sev === 'critical' ? 'var(--lb-accent)' : 'var(--lb-sev-medium)'}; font-size: 12px;">
                            <span style="color: ${w.sev === 'critical' ? 'var(--lb-accent)' : 'var(--lb-sev-medium)'};">!</span>
                            <span class="lb-dim">${escapeHtml(w.msg)}</span>
                        </li>
                    `).join('')}
                </ul>
            `);
        }

        if (f.raw_output) {
            html += panel('Raw Analysis Output', codeBlock(f.raw_output, { label: 'Output' }));
        }

        ctx.element.innerHTML = html;
    },
};
