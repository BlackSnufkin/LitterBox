// app/static/js/results/tools/rededr.js
import { errorPanel, cleanState, threatState, statRow, panel, kvGrid, tag, escapeHtml } from './_shared.js';
import { formatBytes } from '../renderers.js';

export default {
    id: 'rededr',
    elementId: 'redEdrResults',
    statsElementId: 'redEdrStats',

    render(results, ctx) {
        if (results.status === 'error') {
            ctx.element.innerHTML = errorPanel(results.error, results.error_details);
            return;
        }

        const findings = results.findings || {};
        const isEmpty = !findings.process_info?.pid &&
                        !findings.loaded_dlls?.length &&
                        !findings.threads?.length &&
                        !findings.image_loads?.length;

        const isPidScan = window.location.pathname.match(/\/analyze\/dynamic\/\d+$/);

        if (isEmpty) {
            ctx.statsElement.innerHTML = '';
            ctx.element.innerHTML = isPidScan
                ? cleanState('RedEdr Not Initialised', 'No data available — RedEdr did not initialise for this PID-based scan.')
                : threatState('No Analysis Data Available', 'Refresh the page to initiate a new scan.');
            return;
        }

        const proc = findings.process_info || {};
        const loadedDlls = findings.loaded_dlls || [];
        const threads = findings.threads || [];
        const imageLoads = findings.image_loads || [];
        const imageUnloads = findings.image_unloads || [];
        const cpuChanges = findings.cpu_priority_changes || [];
        const timeline = findings.timeline || [];
        const summary = findings.summary || {};

        ctx.statsElement.innerHTML = statRow([
            { label: 'Total Events',    value: summary.total_events || 0,          severity: 'info' },
            { label: 'DLLs Loaded',     value: summary.total_dlls || 0,            severity: 'info' },
            { label: 'Child Processes', value: summary.total_child_processes || 0, severity: 'info' },
            { label: 'Active Threads',  value: summary.total_threads || 0,         severity: 'info' },
        ]);

        let html = '';

        // Process Details
        const procBadges = [];
        procBadges.push(proc.is_protected_process ? tag('clean', 'Protected') : tag('info', 'Standard'));
        if (proc.is_debugged) procBadges.push(tag('medium', 'Debugged'));

        html += `
            <div class="lb-panel">
                <div class="lb-panel-hdr">
                    <span class="lb-glyph">▸</span>Process Details
                    <span style="margin-left:auto; display:flex; gap: 6px;">${procBadges.join('')}</span>
                </div>
                <div class="lb-panel-body">
                    ${kvGrid([
                        ['Command Line',      proc.commandline],
                        ['Working Directory', proc.working_dir],
                        ['Process ID',        proc.pid],
                        ['Image Path',        proc.image_path],
                    ], 2)}
                </div>
            </div>
        `;

        // Timeline
        if (timeline.length) {
            html += panel('Event Timeline', `
                <div style="display: flex; flex-direction: column;">
                    ${timeline.map(event => `
                        <div style="display: grid; grid-template-columns: 110px 130px 1fr; gap: 12px; padding: 6px 0; border-bottom: 1px dashed var(--lb-border); font-size: 11px;">
                            <span class="lb-mono lb-muted">${escapeHtml(event.time || 'N/A')}</span>
                            <span class="lb-strong">${escapeHtml(event.type || '')}</span>
                            <span class="lb-dim">${escapeHtml(event.details || '')}</span>
                        </div>
                    `).join('')}
                </div>
            `, `${timeline.length} events`);
        }

        // CPU Priority Changes
        if (cpuChanges.length) {
            html += panel('CPU Priority Changes', `
                <table class="lb-table">
                    <thead><tr><th>Thread ID</th><th>Old</th><th>New</th><th>Time</th></tr></thead>
                    <tbody>
                        ${cpuChanges.map(c => `
                            <tr>
                                <td class="lb-mono">${escapeHtml(String(c.thread_id))}</td>
                                <td class="lb-mono">${escapeHtml(String(c.old_priority))}</td>
                                <td class="lb-mono">${escapeHtml(String(c.new_priority))}</td>
                                <td class="lb-mono lb-muted">${escapeHtml(c.time || 'N/A')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `, String(cpuChanges.length));
        }

        // DLLs / Images / Threads sub-tabs
        html += `
            <div class="lb-panel">
                <div style="display: flex; border-bottom: 1px solid var(--lb-border);">
                    <button onclick="switchInnerTab('dlls')" class="tab-button active" style="padding: 8px 14px; background: transparent; color: var(--lb-text); border: 0; border-bottom: 2px solid var(--lb-accent-soft); font-family: inherit; font-size: 12px; cursor: pointer;">DLLs (${loadedDlls.length})</button>
                    <button onclick="switchInnerTab('images')" class="tab-button" style="padding: 8px 14px; background: transparent; color: var(--lb-text-dim); border: 0; border-bottom: 2px solid transparent; font-family: inherit; font-size: 12px; cursor: pointer;">Images (${imageLoads.length + imageUnloads.length})</button>
                    <button onclick="switchInnerTab('threads')" class="tab-button" style="padding: 8px 14px; background: transparent; color: var(--lb-text-dim); border: 0; border-bottom: 2px solid transparent; font-family: inherit; font-size: 12px; cursor: pointer;">Threads (${threads.length})</button>
                </div>

                <div id="dlls-tab" class="tab-content">
                    <div class="lb-panel-body">
                        <table class="lb-table">
                            <thead><tr><th>Name</th><th>Base</th><th>Size</th></tr></thead>
                            <tbody>
                                ${loadedDlls.map(dll => `
                                    <tr>
                                        <td class="lb-mono">${escapeHtml(dll.name || 'Unknown')}</td>
                                        <td class="lb-mono lb-muted">${dll.addr ? '0x' + dll.addr.toString(16) : 'N/A'}</td>
                                        <td class="lb-mono lb-muted">${dll.size ? formatBytes(dll.size) : 'N/A'}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div id="images-tab" class="tab-content hidden">
                    <div class="lb-panel-body">
                        <div style="display: flex; gap: 8px; margin-bottom: 12px;">
                            <button onclick="filterImages('loads')" class="lb-btn" style="padding: 4px 10px; font-size: 11px;">Loads (${imageLoads.length})</button>
                            <button onclick="filterImages('unloads')" class="lb-btn" style="padding: 4px 10px; font-size: 11px;">Unloads (${imageUnloads.length})</button>
                        </div>
                        <div id="image-loads">
                            <table class="lb-table">
                                <thead><tr><th>Image</th><th>Base</th><th>Size</th></tr></thead>
                                <tbody>
                                    ${imageLoads.map(img => `
                                        <tr>
                                            <td class="lb-mono">${escapeHtml(img.image_name?.split('\\').pop() || 'Unknown')}</td>
                                            <td class="lb-mono lb-muted">${img.base ? '0x' + img.base.toString(16) : 'N/A'}</td>
                                            <td class="lb-mono lb-muted">${formatBytes(img.size || 0)}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                        <div id="image-unloads" class="hidden">
                            <table class="lb-table">
                                <thead><tr><th>Image</th><th>Base</th><th>Size</th></tr></thead>
                                <tbody>
                                    ${imageUnloads.map(img => `
                                        <tr>
                                            <td class="lb-mono">${escapeHtml(img.image_name?.split('\\').pop() || 'Unknown')}</td>
                                            <td class="lb-mono lb-muted">${img.base ? '0x' + img.base.toString(16) : 'N/A'}</td>
                                            <td class="lb-mono lb-muted">${formatBytes(img.size || 0)}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div id="threads-tab" class="tab-content hidden">
                    <div class="lb-panel-body">
                        <table class="lb-table">
                            <thead><tr><th>Thread ID</th><th>Process ID</th><th>Start Address</th><th>Stack Base</th></tr></thead>
                            <tbody>
                                ${threads.map(t => `
                                    <tr>
                                        <td class="lb-mono">${escapeHtml(String(t.thread_id))}</td>
                                        <td class="lb-mono lb-muted">${escapeHtml(String(t.process_id))}</td>
                                        <td class="lb-mono lb-muted">${t.start_addr ? '0x' + t.start_addr.toString(16) : 'N/A'}</td>
                                        <td class="lb-mono lb-muted">${t.stack_base ? '0x' + t.stack_base.toString(16) : 'N/A'}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;

        ctx.element.innerHTML = html;

        // Sub-tab navigation (define once)
        if (!window.switchInnerTab) {
            window.switchInnerTab = function(tabName) {
                document.querySelectorAll('#redEdrTab .tab-content').forEach(c => c.classList.add('hidden'));
                document.getElementById(`${tabName}-tab`)?.classList.remove('hidden');

                const buttons = document.querySelectorAll('#redEdrTab .tab-button');
                buttons.forEach(b => {
                    b.classList.remove('active');
                    b.style.color = 'var(--lb-text-dim)';
                    b.style.borderBottom = '2px solid transparent';
                });
                const active = document.querySelector(`#redEdrTab [onclick="switchInnerTab('${tabName}')"]`);
                if (active) {
                    active.classList.add('active');
                    active.style.color = 'var(--lb-text)';
                    active.style.borderBottom = '2px solid var(--lb-accent-soft)';
                }
            };
        }

        if (!window.filterImages) {
            window.filterImages = function(type) {
                const loads = document.getElementById('image-loads');
                const unloads = document.getElementById('image-unloads');
                if (!loads || !unloads) return;
                if (type === 'loads')   { loads.classList.remove('hidden'); unloads.classList.add('hidden'); }
                else                    { loads.classList.add('hidden');     unloads.classList.remove('hidden'); }
            };
        }
    },
};
