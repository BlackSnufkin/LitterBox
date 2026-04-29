// app/static/js/results/tools/pe_sieve.js
import { errorPanel, cleanState, statRow, panel, codeBlock, escapeHtml } from './_shared.js';

export default {
    id: 'pe_sieve',
    elementId: 'peSieveResults',

    render(results, ctx) {
        if (results.status === 'error') {
            ctx.element.innerHTML = errorPanel(results.error);
            return;
        }

        const f = results.findings || {};
        const isClean = (f.total_suspicious || 0) === 0;

        let html = statRow([
            { label: 'Status',        value: isClean ? 'Clean' : 'Detected', severity: isClean ? 'clean' : 'critical' },
            { label: 'Total Scanned', value: f.total_scanned || 0,             severity: 'info' },
            { label: 'Modifications', value: f.total_suspicious || 0,          severity: isClean ? 'info' : 'critical' },
        ]);

        if (isClean) {
            html += cleanState('No memory modifications observed', 'PE-Sieve scan completed without findings.');
            ctx.element.innerHTML = html;
            return;
        }

        const breakdown = [
            { label: 'Hooked',           value: f.hooked },
            { label: 'Replaced',         value: f.replaced },
            { label: 'Headers Modified', value: f.hdrs_modified },
            { label: 'IAT Hooks',        value: f.iat_hooks },
            { label: 'Implanted',        value: f.implanted },
            { label: 'Implanted PE',     value: f.implanted_pe },
            { label: 'Implanted shc',    value: f.implanted_shc },
            { label: 'Unreachable',      value: f.unreachable },
            { label: 'Other',            value: f.other },
        ];

        html += panel('Indicator Breakdown', `
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;">
                ${breakdown.map(item => `
                    <div style="padding: 10px; border: 1px solid ${item.value > 0 ? 'rgba(248, 113, 113, 0.22)' : 'var(--lb-border)'};">
                        <div class="lb-eyebrow" style="margin-bottom: 4px;">${escapeHtml(item.label)}</div>
                        <div class="lb-mono lb-strong" style="font-size: 16px; color: ${item.value > 0 ? 'var(--lb-accent)' : 'var(--lb-text)'};">${item.value || 0}</div>
                    </div>
                `).join('')}
            </div>
        `);

        if (f.raw_output) {
            html += panel('Raw Analysis Output', codeBlock(f.raw_output, { label: 'Output' }));
        }

        ctx.element.innerHTML = html;
    },
};
