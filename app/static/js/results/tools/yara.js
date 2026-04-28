// app/static/js/results/tools/yara.js
import { errorPanel, cleanState, statRow, panel, kvGrid, tag, escapeHtml } from './_shared.js';

export default {
    id: 'yara',
    elementId: 'yaraResults',
    statsElementId: 'yaraStats',

    render(results, ctx) {
        if (results.status === 'error') {
            ctx.element.innerHTML = errorPanel(results.error);
            return;
        }

        const matches = Array.isArray(results.matches) ? results.matches : [];
        const matchCount = matches.length;
        const isClean = matchCount === 0;
        const totalStrings = matches.reduce((acc, m) => acc + (Array.isArray(m.strings) ? m.strings.length : 0), 0);
        const highestSeverity = matches.length > 0 ? Math.max(...matches.map(m => parseInt(m.metadata?.severity || 0))) : 0;

        ctx.statsElement.innerHTML = statRow([
            { label: 'Rule Matches',  value: matchCount,    severity: isClean ? 'clean' : 'critical' },
            { label: 'Total Strings', value: totalStrings,  severity: 'info' },
            { label: 'Status',        value: isClean ? 'Clean' : `Sev ${highestSeverity}`,
                                      severity: isClean ? 'clean' : (highestSeverity > 50 ? 'critical' : 'medium') },
        ]);

        let html = '';

        if (results.scan_info?.target) {
            html += panel('Target', `
                <div class="lb-mono lb-strong" style="font-size: 12px; word-break: break-all;">${escapeHtml(results.scan_info.target)}</div>
                ${results.scan_info.rules_file ? `<div class="lb-muted" style="font-size: 11px; margin-top: 4px;">Rules: ${escapeHtml(results.scan_info.rules_file)}</div>` : ''}
            `);
        }

        if (isClean) {
            html += cleanState('No rules matched', 'All YARA rules passed without matching.');
            ctx.element.innerHTML = html;
            return;
        }

        const sortedMatches = [...matches].sort((a, b) =>
            (parseInt(b.metadata?.severity) || 0) - (parseInt(a.metadata?.severity) || 0)
        );

        const labelMap = {
            threat_name:   'Match',
            rule_filepath: 'Rule File',
            creation_date: 'Created',
            id:            'Rule ID',
        };
        const metaOrder = ['threat_name', 'rule_filepath', 'creation_date', 'id'];

        html += sortedMatches.map((match, i) => {
            const severity = parseInt(match.metadata?.severity || 0);
            const sev = severity > 50 ? 'critical' : 'medium';
            const strings = Array.isArray(match.strings) ? match.strings : [];

            const metaPairs = metaOrder
                .filter(k => match.metadata?.[k])
                .map(k => [labelMap[k], match.metadata[k]]);

            return `
                <div class="lb-panel">
                    <div class="lb-panel-hdr">
                        <span class="lb-glyph">▸</span>
                        <span class="lb-mono" style="color: ${sev === 'critical' ? 'var(--lb-accent)' : 'var(--lb-sev-medium)'};">#${i + 1} ${escapeHtml(match.rule)}</span>
                        <span style="margin-left: auto; display: flex; gap: 6px;">
                            ${tag(sev, `Sev ${severity}`)}
                            ${strings.length ? `<span class="lb-tag muted">${strings.length} strings</span>` : ''}
                        </span>
                    </div>
                    ${metaPairs.length ? `<div class="lb-panel-body">${kvGrid(metaPairs, 2)}</div>` : ''}
                    ${strings.length ? `
                        <div class="lb-panel-body" style="border-top: 1px solid var(--lb-border);">
                            <div class="lb-eyebrow" style="margin-bottom: 6px;">String Matches</div>
                            <div style="display:flex; flex-direction:column; gap: 6px;">
                                ${strings.map(str => `
                                    <div style="border: 1px solid var(--lb-border); padding: 8px;">
                                        <div style="display:flex; align-items:center; gap:8px; margin-bottom: 4px;">
                                            <span class="lb-mono lb-muted" style="font-size: 11px;">${escapeHtml(str.offset || '')}</span>
                                            ${str.identifier ? `<span class="lb-tag muted">${escapeHtml(str.identifier)}</span>` : ''}
                                            ${str.data_type ? `<span class="lb-tag muted">${escapeHtml(str.data_type)}</span>` : ''}
                                        </div>
                                        <pre class="lb-mono" style="background: var(--lb-bg); padding: 6px 8px; font-size: 11px; color: var(--lb-text-dim); white-space: pre-wrap; word-break: break-all; max-height: 120px; overflow: auto; margin: 0;">${escapeHtml(str.data || '')}</pre>
                                    </div>
                                `).join('')}
                            </div>
                        </div>` : ''}
                </div>`;
        }).join('');

        ctx.element.innerHTML = html;
    },
};
