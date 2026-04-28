// app/static/js/results/tools/summary.js
//
// Special "tool" — populates the top-of-page Summary tab (target details,
// total detections, scanner table, scan duration, payload output hand-off).
//
// Receives the full data.results object, not a single tool's results.

import { panel, kvGrid, summaryRow, escapeHtml } from './_shared.js';

export default {
    id: 'summary',
    // The summary renderer writes to several IDs (targetDetails, overallStatus,
    // totalDetections, scannerResultsBody, scanDuration). It doesn't have a
    // single root container, so we point elementId at scannerResultsBody — the
    // table body it always populates — to satisfy the registry's null check.
    elementId: 'scannerResultsBody',
    statsElementId: 'scannerResultsBody',

    render(results, ctx) {
        // Early-termination case
        if (results.status === 'early_termination') {
            const totalEl = document.getElementById('totalDetections');
            const overEl  = document.getElementById('overallStatus');
            if (totalEl) totalEl.textContent = '-';
            if (overEl)  { overEl.textContent = 'Analysis Failed'; overEl.style.color = 'var(--lb-accent)'; }

            if (ctx.statsElement) {
                ctx.statsElement.innerHTML = `
                    <tr>
                        <td colspan="4" style="padding: 16px; text-align: center;">
                            <div class="lb-strong" style="color: var(--lb-accent); margin-bottom: 4px;">Process terminated before analysis could complete</div>
                            <div class="lb-muted" style="font-size: 11px;">${escapeHtml(results.error || 'Process terminated early')}${
                                results.analysis_metadata?.total_duration
                                    ? ` (terminated after ${results.analysis_metadata.total_duration}s)`
                                    : ''
                            }</div>
                        </td>
                    </tr>`;
            }

            const targetEl = document.getElementById('targetDetails');
            if (targetEl) {
                targetEl.innerHTML = `
                    <div class="lb-empty threats" style="flex-direction: column; align-items: flex-start; padding: 12px 16px;">
                        <div class="lb-strong">Analysis Failed</div>
                        <div class="lb-muted" style="font-size: 11px;">Process terminated before analysis could complete. No results available.</div>
                    </div>`;
            }
            return;
        }

        // Target details
        const targetEl = document.getElementById('targetDetails');
        if (targetEl) {
            if (results.moneta?.findings?.process_info) {
                const info = results.moneta.findings.process_info;
                targetEl.innerHTML = panel('Target Process', kvGrid([
                    ['Name', info.name],
                    ['PID',  info.pid],
                    ['Path', info.path],
                ], 1));
            } else {
                const filePath = results.checkplz?.findings?.scan_results?.file_path || 'No file path available';
                targetEl.innerHTML = panel('Target File', `
                    <div class="lb-mono lb-strong" style="font-size: 12px; word-break: break-all;">${escapeHtml(filePath)}</div>
                `);
            }
        }

        // Build scanner table rows
        let totalDetections = 0;
        const rows = [];

        if (results.yara) {
            const matches = Array.isArray(results.yara.matches) ? results.yara.matches : [];
            totalDetections += matches.length;
            rows.push(summaryRow({
                name: 'YARA',
                triggered: matches.length > 0,
                count: matches.length,
                detail: matches.length > 0 ? `${matches.length} rule match${matches.length === 1 ? '' : 'es'}` : 'No rules matched',
            }));
        }

        if (results.pe_sieve) {
            const susp = results.pe_sieve.findings?.total_suspicious || 0;
            totalDetections += susp;
            rows.push(summaryRow({
                name: 'PE-sieve',
                triggered: susp > 0,
                count: susp,
                detail: susp > 0 ? `${susp} memory modification${susp === 1 ? '' : 's'} observed` : 'No memory modifications observed',
            }));
        }

        if (results.moneta) {
            const f = results.moneta.findings || {};
            const susp = (f.total_private_rwx || 0) + (f.total_private_rx || 0) + (f.total_modified_code || 0)
                       + (f.total_heap_executable || 0) + (f.total_modified_pe_header || 0)
                       + (f.total_inconsistent_x || 0) + (f.total_threads_non_image || 0)
                       + (f.total_missing_peb || 0) + (f.total_mismatching_peb || 0);
            const isClean = susp === 0;
            totalDetections += susp;
            rows.push(summaryRow({
                name: 'Moneta',
                triggered: !isClean,
                count: susp,
                detail: isClean ? 'No anomalies observed' : 'Memory anomalies observed',
            }));
        }

        if (results.checkplz) {
            const f = results.checkplz.findings || {};
            const hasDetection = !!f.scan_results?.detection_offset;
            if (hasDetection) totalDetections++;
            rows.push(summaryRow({
                name: 'CheckPlz',
                triggered: hasDetection,
                count: hasDetection ? 1 : 0,
                detail: hasDetection ? (f.initial_threat || 'Signature triggered') : 'No signatures triggered',
            }));
        }

        if (results.patriot) {
            const total = results.patriot.findings?.findings?.length || 0;
            totalDetections += total;
            rows.push(summaryRow({
                name: 'Patriot',
                triggered: total > 0,
                count: total,
                detail: total > 0 ? `${total} indicator${total === 1 ? '' : 's'} observed` : 'No indicators observed',
            }));
        }

        if (results.hsb) {
            const total = results.hsb.findings?.summary?.total_findings || 0;
            totalDetections += total;
            rows.push(summaryRow({
                name: 'Hunt-Sleeping-Beacons',
                triggered: total > 0,
                count: total,
                detail: total > 0 ? 'Sleep-pattern indicators observed' : 'No sleep-pattern indicators',
            }));
        }

        // Update summary stats
        const totalEl = document.getElementById('totalDetections');
        const overEl  = document.getElementById('overallStatus');
        if (totalEl) totalEl.textContent = totalDetections;
        if (overEl) {
            overEl.textContent = totalDetections > 0 ? 'Detections' : 'Clean';
            overEl.style.color = totalDetections > 0 ? 'var(--lb-accent)' : 'var(--lb-sev-low)';
        }

        // Set table content
        if (ctx.statsElement) {
            ctx.statsElement.innerHTML = rows.join('');
        }

        // Mirror scan duration
        const durEl = document.getElementById('scanDuration');
        const timerEl = document.getElementById('analysisTimer');
        if (durEl && timerEl) durEl.textContent = timerEl.textContent;

        // Process output (dynamic only)
        if (results.process_output) {
            window.updatePayloadOutput?.(results);
        }
    },
};
