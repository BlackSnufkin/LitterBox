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
                            <div class="lb-muted" style="font-size: 12px;">${escapeHtml(results.error || 'Process terminated early')}${
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
                        <div class="lb-muted" style="font-size: 12px;">Process terminated before analysis could complete. No results available.</div>
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
                    <div class="lb-mono lb-strong" style="font-size: 13px; word-break: break-all;">${escapeHtml(filePath)}</div>
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

        if (results.edr) {
            const r = results.edr;
            const summary = r.summary || {};
            const totalAlerts = summary.total_alerts != null
                ? summary.total_alerts
                : (Array.isArray(r.alerts) ? r.alerts.length : 0);
            const killedByEdr = !!(r.execution && r.execution.killed_by_edr);
            totalDetections += totalAlerts;
            const status = r.status || 'unknown';
            let detail;
            let isFailureState = false;
            let isPolling = false;
            if (status === 'agent_unreachable')         { detail = 'Agent unreachable'; isFailureState = true; }
            else if (status === 'busy')                 { detail = 'Agent busy with another run'; isFailureState = true; }
            else if (status === 'partial')              { detail = 'Run completed but Elastic query failed'; isFailureState = true; }
            else if (status === 'error')                { detail = `Error: ${r.error || 'unknown'}`; isFailureState = true; }
            else if (status === 'polling_alerts' && summary.blocked_by_av) { detail = 'EDR blocked spawn — correlating alerts…'; isPolling = true; }
            else if (status === 'polling_alerts' && killedByEdr) { detail = 'Killed by EDR — correlating alerts…'; isPolling = true; }
            else if (status === 'polling_alerts')       { detail = 'Exec finished — correlating alerts…'; isPolling = true; }
            else if (status === 'blocked_by_av')        detail = 'Blocked by EDR before execution';
            else if (killedByEdr && totalAlerts > 0)    detail = `Killed by EDR · ${totalAlerts} alert${totalAlerts === 1 ? '' : 's'} raised`;
            else if (totalAlerts > 0)                   detail = `${totalAlerts} alert${totalAlerts === 1 ? '' : 's'} raised`;
            else                                        detail = 'No alerts raised';
            rows.push(summaryRow({
                name: r.display_name || r.profile || 'EDR',
                triggered: totalAlerts > 0 || status === 'blocked_by_av' || killedByEdr || isFailureState || isPolling,
                count: totalAlerts,
                detail,
            }));
        }

        // Update summary stats. EDR runs that are still in their Phase-2
        // poll window haven't finished correlating yet — show that
        // explicitly instead of a misleading "Clean" green when the
        // count happens to be 0.
        const edrPolling = !!(results.edr && results.edr.status === 'polling_alerts');
        const totalEl = document.getElementById('totalDetections');
        const overEl  = document.getElementById('overallStatus');
        if (totalEl) totalEl.textContent = totalDetections;
        if (overEl) {
            if (edrPolling && totalDetections === 0) {
                overEl.textContent = 'Correlating…';
                overEl.style.color = 'var(--lb-accent-soft)';
            } else {
                overEl.textContent = totalDetections > 0 ? 'Detections' : 'Clean';
                overEl.style.color = totalDetections > 0 ? 'var(--lb-accent)' : 'var(--lb-sev-low)';
            }
        }

        // Set table content
        if (ctx.statsElement) {
            ctx.statsElement.innerHTML = rows.join('');
        }

        // Mirror scan duration
        const durEl = document.getElementById('scanDuration');
        const timerEl = document.getElementById('analysisTimer');
        if (durEl && timerEl) durEl.textContent = timerEl.textContent;

        // Process Output panel — populated for both dynamic runs (which
        // ship `process_output`) and EDR runs (which carry stdout/stderr
        // under `edr.execution`). The EDR side is synthesized so the same
        // PayloadManager logic renders both.
        if (results.process_output) {
            window.updatePayloadOutput?.(results);
        } else if (results.edr && results.edr.execution &&
                   (results.edr.execution.stdout || results.edr.execution.stderr)) {
            const e = results.edr.execution;
            window.updatePayloadOutput?.({
                process_output: {
                    stdout: e.stdout || '',
                    stderr: e.stderr || '',
                    had_output: !!(e.stdout || e.stderr),
                    output_truncated: false,
                },
            });
        }
    },
};
