// app/static/js/results/tools/stringnalyzer.js
import { errorPanel, statRow } from './_shared.js';
import { renderSection } from '../renderers.js';

export default {
    id: 'stringnalyzer',
    elementId: 'StringnalyzerResults',
    statsElementId: 'StringnalyzerStats',

    render(results, ctx) {
        if (results.status === 'error') {
            ctx.element.innerHTML = errorPanel(results.error);
            return;
        }

        const findings = results.findings || {};

        ctx.statsElement.innerHTML = statRow([
            { label: 'File Path',     value: findings.file_path || 'N/A', severity: 'info' },
            { label: 'Total Strings', value: findings.total_strings || 0, severity: 'info' },
        ]);

        const downloadBtn = document.getElementById('downloadResultsBtn');
        if (downloadBtn && !downloadBtn._wired) {
            downloadBtn._wired = true;
            downloadBtn.addEventListener('click', () => {
                const filePath = results.findings?.file_path || 'unknown';
                const fullFileName = filePath.split('\\').pop().split('/').pop();
                const actualFileName = fullFileName.split('_').pop();
                const downloadName = `stringnalyzer_${actualFileName.replace('.exe', '')}.json`;
                const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = downloadName;
                a.click();
                URL.revokeObjectURL(url);
            });
        }

        const sections = [
            ['Notable Strings',        findings.found_suspicious_strings],
            ['Notable Functions',      findings.found_suspicious_functions],
            ['URLs',                   findings.found_url],
            ['DLLs Referenced',        findings.found_dll],
            ['IP Addresses',           findings.found_ip],
            ['Paths',                  findings.found_path],
            ['Files Referenced',       findings.found_file],
            ['Commands',               findings.found_commands],
            ['Functions',              findings.found_functions],
            ['Error Messages',         findings.found_error_messages],
            ['Network Indicators',     findings.found_network_indicators],
            ['Registry Keys',          findings.found_registry_keys],
            ['File Operations',        findings.found_file_operations],
            ['Email Addresses',        findings.found_emails],
            ['Domains',                findings.found_domains],
            ['Interesting Strings',    findings.found_interesting_strings],
        ];

        ctx.element.innerHTML = sections
            .map(([title, items]) => renderSection(title, items))
            .filter(Boolean)
            .join('');
    },
};
