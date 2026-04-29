// app/static/js/results/tools/patriot.js
import { errorPanel, cleanState, statRow, panel, kvGrid, tag, escapeHtml } from './_shared.js';

export default {
    id: 'patriot',
    elementId: 'patriotResults',
    statsElementId: 'patriotStats',

    render(results, ctx) {
        if (results.status === 'error') {
            ctx.element.innerHTML = errorPanel(results.error);
            return;
        }

        const data = results.findings || {};
        const proc = data.process_info || {};
        const mem = data.memory_stats || {};
        const sum = data.scan_summary || {};
        const findings = data.findings || [];
        const isClean = findings.length === 0;

        ctx.statsElement.innerHTML = statRow([
            { label: 'Status',         value: isClean ? 'Clean' : 'Detected', severity: isClean ? 'clean' : 'critical' },
            { label: 'Memory Regions', value: mem.total_regions || 0,           severity: 'info' },
            { label: 'Total Findings', value: sum.total_findings || 0,          severity: isClean ? 'info' : 'critical' },
        ]);

        let html = panel('Process Information', kvGrid([
            ['PID',              proc.pid],
            ['Process Name',     proc.process_name],
            ['Elevation Status', proc.elevation_status],
            ['Memory',           `Private ${mem.private_memory ?? '?'} MB · Executable ${mem.executable_memory ?? '?'} MB`, false],
        ], 2));

        if (isClean) {
            html += cleanState('No indicators observed', `Scan completed in ${sum.duration || 0}s.`);
        } else {
            const findingsByType = sum.findings_by_type || {};
            if (Object.keys(findingsByType).length > 0) {
                html += panel('Indicators By Type', `
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;">
                        ${Object.entries(findingsByType).map(([type, count]) => `
                            <div style="padding: 10px; border: 1px solid rgba(248, 113, 113, 0.22);">
                                <div class="lb-eyebrow" style="margin-bottom: 4px;">${escapeHtml(type)}</div>
                                <div class="lb-mono lb-strong" style="font-size: 16px; color: var(--lb-accent);">${count}</div>
                            </div>
                        `).join('')}
                    </div>
                `);
            }

            html += findings.map(f => `
                <div class="lb-panel">
                    <div class="lb-panel-hdr">
                        <span class="lb-glyph">▸</span>
                        <span class="lb-mono" style="color: var(--lb-accent);">#${f.finding_number} ${escapeHtml(f.type)}</span>
                        <span style="margin-left:auto; display:flex; gap:6px; align-items:center;">
                            ${tag(f.level === 'CRITICAL' || f.level === 'HIGH' ? 'critical' : 'medium', f.level || 'INFO')}
                            <span class="lb-muted" style="font-size: 11px;">${escapeHtml(f.timestamp || '')}</span>
                        </span>
                    </div>
                    <div class="lb-panel-body">
                        ${kvGrid([
                            ['Process', `${f.process_name} (PID ${f.pid})`, false],
                            ['Level',   f.level, false],
                        ], 2)}
                        <div style="margin-top: 10px;">
                            <div class="lb-eyebrow" style="margin-bottom: 4px;">Details</div>
                            <div class="lb-mono lb-dim" style="font-size: 11px; padding: 6px 8px; background: var(--lb-bg); border-left: 1px solid var(--lb-border-hi); word-break: break-all;">${escapeHtml(f.details || '')}</div>
                        </div>
                        ${f.parsed_details ? `
                            <div style="margin-top: 10px;">
                                <div class="lb-eyebrow" style="margin-bottom: 4px;">Parsed Details</div>
                                ${kvGrid(Object.entries(f.parsed_details).map(([k, v]) => [k, v]), 2)}
                            </div>` : ''}
                        ${f.module_information ? `
                            <div style="margin-top: 10px;">
                                <div class="lb-eyebrow" style="margin-bottom: 4px;">Module Information</div>
                                ${kvGrid(Object.entries(f.module_information).map(([k, v]) => [k, v]), 2)}
                            </div>` : ''}
                    </div>
                </div>
            `).join('');
        }

        ctx.element.innerHTML = html;
    },
};
