// app/static/js/results/tools/checkplz.js
import { errorPanel, cleanState, statRow, panel, kvGrid, codeBlock } from './_shared.js';

export default {
    id: 'checkplz',
    elementId: 'threatCheckResults',
    statsElementId: 'threatCheckStats',

    render(results, ctx) {
        if (results.status === 'error') {
            ctx.element.innerHTML = errorPanel(results.error);
            return;
        }

        const findings = results.findings || {};
        const scan = findings.scan_results || {};
        const isClean = !findings.initial_threat && !scan.detection_offset;

        ctx.statsElement.innerHTML = statRow([
            { label: 'Status', value: isClean ? 'Clean' : (findings.initial_threat || 'Threat'),
                               severity: isClean ? 'clean' : 'critical' },
            { label: 'Scan Duration', value: typeof scan.scan_duration === 'number' ? scan.scan_duration.toFixed(3) + 's' : 'N/A',
                                      severity: 'info' },
            { label: 'Iterations', value: scan.search_iterations || 'N/A', severity: 'info' },
        ]);

        let html = '';

        html += panel('File Information', kvGrid([
            ['File Path', scan.file_path || 'N/A'],
            ['File Size', scan.file_size || 'N/A', false],
        ], 2));

        if (isClean) {
            html += cleanState('No threats detected', 'Security scan completed successfully.');
        } else {
            html += panel('Threat Detection', kvGrid([
                ['Detection Offset',       scan.detection_offset || '—'],
                ['Relative Location',      scan.relative_location || '—', false],
                ['Final Threat Detection', scan.final_threat_detection || '—', false],
            ], 2), 'CRITICAL');

            if (scan.hex_dump) {
                html += panel('Hex Dump (±128 bytes around detection)', codeBlock(scan.hex_dump, { label: 'Bytes' }));
            }
        }

        ctx.element.innerHTML = html;
    },
};
