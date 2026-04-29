// app/static/js/results/tools/hsb.js
import { errorPanel, cleanState, statRow, kvGrid, tag, escapeHtml } from './_shared.js';

const SEV_TO_TAG = {
    CRITICAL: 'critical',
    HIGH:     'critical',
    MID:      'medium',
    LOW:      'info',
};

export default {
    id: 'hsb',
    elementId: 'hsbResults',
    statsElementId: 'hsbStats',

    render(results, ctx) {
        if (results.status === 'error') {
            ctx.element.innerHTML = errorPanel(results.error);
            return;
        }

        const data = results.findings || {};
        const summary = data.summary || {};
        const firstDetection = (data.detections && data.detections.length > 0) ? data.detections[0] : null;
        const hasFindings = !!(firstDetection && firstDetection.findings && firstDetection.findings.length > 0);
        const processName = firstDetection?.process_name ?? 'N/A';
        const processPid = firstDetection?.pid ?? 'N/A';

        ctx.statsElement.innerHTML = statRow([
            { label: 'Status',   value: hasFindings ? 'Detected' : 'Clean', severity: hasFindings ? 'critical' : 'clean' },
            { label: 'Findings', value: summary.total_findings || 0,          severity: hasFindings ? 'critical' : 'info' },
            { label: 'Threads',  value: summary.scanned_threads || 0,         severity: 'info' },
            { label: 'PID',      value: processPid,                           severity: 'info' },
            { label: 'Duration', value: ((summary.duration || 0)).toFixed(3) + 's', severity: 'info' },
        ]);

        if (!hasFindings) {
            ctx.element.innerHTML = cleanState('No sleep-pattern indicators', `Process ${processName} (PID ${processPid}) shows no beacon-like sleep behaviour.`);
            return;
        }

        const findingsByThread = {};
        firstDetection.findings.forEach(f => {
            const tid = f.thread_id || 'process';
            (findingsByThread[tid] = findingsByThread[tid] || []).push(f);
        });

        let html = `
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
                <span class="lb-strong" style="color: var(--lb-accent);">${escapeHtml(processName)}</span>
                <span class="lb-muted" style="font-size: 12px;">(PID ${escapeHtml(String(processPid))})</span>
            </div>
        `;

        html += Object.entries(findingsByThread).map(([tid, items]) => `
            <div class="lb-panel">
                <div class="lb-panel-hdr">
                    <span class="lb-glyph">▸</span>${tid === 'process' ? 'Process-wide Indicators' : `Thread ${tid}`}
                    <span class="lb-panel-badge">${items.length}</span>
                </div>
                <div class="lb-panel-body">
                    ${items.map(f => {
                        const sev = SEV_TO_TAG[f.severity] || 'info';
                        const borderColor =
                            sev === 'critical' ? 'rgba(248, 113, 113, 0.22)' :
                            sev === 'medium'   ? 'rgba(250, 204, 21, 0.22)' :
                                                 'var(--lb-border-hi)';
                        return `
                            <div style="border: 1px solid ${borderColor}; padding: 10px; margin-bottom: 8px;">
                                <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom: 6px;">
                                    <span class="lb-strong" style="font-size: 13px;">${escapeHtml(f.type)}</span>
                                    ${tag(sev, f.severity || 'INFO')}
                                </div>
                                ${f.description ? `<div class="lb-dim" style="font-size: 12px; margin-bottom: 6px;">${escapeHtml(f.description)}</div>` : ''}
                                ${f.details && Object.keys(f.details).length ? kvGrid(
                                    Object.entries(f.details)
                                        .filter(([k]) => k !== 'issue' && k !== 'condition')
                                        .map(([k, v]) => [k.replace(/_/g, ' '), v]),
                                    2
                                ) : ''}
                            </div>
                        `;
                    }).join('')}
                </div>
            </div>
        `).join('');

        ctx.element.innerHTML = html;
    },
};
