// app/static/js/results/tools/rededr.js
import { errorPanel, cleanState, threatState, statRow, panel, kvGrid, tag, escapeHtml } from './_shared.js';
import { formatBytes } from '../renderers.js';

// Windows FILETIME → ISO-ish local time. RedEdr emits
// record.EventHeader.TimeStamp.QuadPart which is 100-ns intervals since
// 1601-01-01 UTC. Unix-epoch (1970) is 116444736000000000 of those.
// Values are too large for JS Number (1.34e17 > 9.0e15 MAX_SAFE_INTEGER),
// so use BigInt for the math.
const FILETIME_UNIX_OFFSET_100NS = 116444736000000000n;

function formatEtwTime(value) {
    if (value === null || value === undefined || value === '' || value === 'N/A') {
        return 'N/A';
    }
    let big;
    try {
        big = typeof value === 'bigint' ? value : BigInt(value);
    } catch {
        return String(value);
    }
    // Heuristic: FILETIME for the current era is ~1.3e17. Anything below
    // 1e15 is more likely unix-epoch milliseconds (RedEdr's get_time()).
    let unixMs;
    if (big > 1000000000000000n) {
        unixMs = Number((big - FILETIME_UNIX_OFFSET_100NS) / 10000n);
    } else if (big > 1000000000000n) {
        unixMs = Number(big);            // already unix ms
    } else if (big > 1000000000n) {
        unixMs = Number(big) * 1000;     // unix seconds
    } else {
        return String(value);
    }
    if (!Number.isFinite(unixMs) || unixMs <= 0) return String(value);
    const d = new Date(unixMs);
    if (Number.isNaN(d.getTime())) return String(value);
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    const ss = String(d.getSeconds()).padStart(2, '0');
    const ms = String(d.getMilliseconds()).padStart(3, '0');
    return `${hh}:${mm}:${ss}.${ms}`;
}

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
                : threatState('No telemetry available', 'Refresh the page to initiate a new scan.');
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
        const childProcesses = findings.child_processes || [];
        const fileOps = findings.file_operations || [];
        const networkActivity = findings.network_activity || [];
        const auditApi = findings.audit_api_calls || [];
        const defenderEvents = findings.defender_events || [];
        const defenderThreats  = defenderEvents.filter(e => e.category === 'threat');
        const defenderScans    = defenderEvents.filter(e => e.category === 'scan');
        const defenderInternal = defenderEvents.filter(e => e.category === 'internal');
        const defenderOther    = defenderEvents.filter(e => e.category === 'other' || !e.category);
        const hasThreatVerdict = defenderThreats.length > 0;

        ctx.statsElement.innerHTML = statRow([
            { label: 'Total Events',    value: summary.total_events || 0,             severity: 'info' },
            { label: 'DLLs Loaded',     value: summary.total_dlls || 0,               severity: 'info' },
            { label: 'Child Processes', value: summary.total_child_processes || 0,    severity: 'info' },
            { label: 'Threads',         value: summary.total_threads || 0,            severity: 'info' },
            { label: 'Network',         value: summary.total_network_activity || 0,   severity: networkActivity.length > 0 ? 'medium' : 'info' },
            { label: 'File Ops',        value: summary.total_file_operations || 0,    severity: 'info' },
            { label: 'Audit API',       value: summary.total_audit_api_calls || 0,    severity: auditApi.length > 0 ? 'medium' : 'info' },
            { label: 'Defender',        value: summary.total_defender_events || 0,    severity: hasThreatVerdict ? 'critical' : (defenderScans.length > 0 ? 'medium' : 'info') },
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

        // Process Tree (parent + spawned children)
        if (childProcesses.length) {
            const escapedRoot = escapeHtml(proc.image_path?.split('\\').pop() || proc.commandline || 'Target');
            html += panel('Process Tree', `
                <div style="display: flex; flex-direction: column; gap: 4px; font-size: 13px;">
                    <div>
                        <span class="lb-mono lb-strong">${escapedRoot}</span>
                        <span class="lb-muted" style="margin-left: 8px;">PID ${escapeHtml(String(proc.pid ?? '?'))}</span>
                    </div>
                    <ul style="list-style: none; margin: 0; padding-left: 18px; display: flex; flex-direction: column; gap: 3px;">
                        ${childProcesses.map(c => `
                            <li style="font-size: 12px;">
                                <span class="lb-muted">└─</span>
                                <span class="lb-mono lb-strong" style="margin-left: 4px;">${escapeHtml((c.image_name || '').split('\\').pop() || 'Unknown')}</span>
                                <span class="lb-muted" style="margin-left: 6px;">PID ${escapeHtml(String(c.pid ?? '?'))}</span>
                                ${c.parent_pid ? `<span class="lb-muted" style="margin-left: 6px;">parent ${escapeHtml(String(c.parent_pid))}</span>` : ''}
                            </li>
                        `).join('')}
                    </ul>
                </div>
            `, `${childProcesses.length} child${childProcesses.length === 1 ? '' : 'ren'}`);
        }

        // Defender events — verdict line up top, then a table only when there's
        // actually something to show. Three buckets:
        //   threat    = real detection (the loud signal)
        //   scan      = Defender behavior monitor engaged with our process
        //               (BmModuleLoad / BmNotificationHandle* / BmOpenProcess)
        //   internal  = Defender's own state plumbing (BmInternal / BmEtw)
        // For most operator-flavored runs the answer is: lots of scans, no
        // threats — meaning Defender looked at the binary and didn't flag it.
        if (defenderEvents.length) {
            const renderDefenderRows = (events) => events.map(e => `
                <tr ${e.is_threat ? 'style="background: rgba(248, 113, 113, 0.04);"' : ''}>
                    <td class="lb-mono">${escapeHtml(e.provider || '')}</td>
                    <td class="lb-mono">${escapeHtml(e.event || '')}</td>
                    <td class="lb-mono lb-muted">${escapeHtml(e.scan_target || '—')}</td>
                    <td>${e.verdict ? tag(e.is_threat ? 'critical' : 'medium', String(e.verdict)) : '<span class="lb-muted">—</span>'}</td>
                    <td class="lb-mono lb-muted">${escapeHtml(formatEtwTime(e.time))}</td>
                </tr>
            `).join('');

            // Headline verdict — the operator's bottom-line answer.
            let verdictLine, verdictColor, headerBadge;
            if (hasThreatVerdict) {
                verdictLine = `Defender flagged the binary — ${defenderThreats.length} threat verdict${defenderThreats.length === 1 ? '' : 's'}.`;
                verdictColor = 'var(--lb-accent-soft)';
                headerBadge = `${defenderThreats.length} threat${defenderThreats.length === 1 ? '' : 's'}`;
            } else if (defenderScans.length > 0) {
                verdictLine = `Defender scanned the binary ${defenderScans.length} time${defenderScans.length === 1 ? '' : 's'} — no threat verdict.`;
                verdictColor = 'var(--lb-sev-low)';
                headerBadge = `${defenderScans.length} scan${defenderScans.length === 1 ? '' : 's'}, no verdict`;
            } else {
                verdictLine = `Defender did not actively scan the binary (${defenderInternal.length + defenderOther.length} internal event${(defenderInternal.length + defenderOther.length) === 1 ? '' : 's'} only).`;
                verdictColor = 'var(--lb-text-dim)';
                headerBadge = `${defenderEvents.length} internal`;
            }

            const breakdownLine = `
                <div class="lb-muted" style="font-size: 12px; margin-top: 4px;">
                    Threats ${defenderThreats.length} · Scan activity ${defenderScans.length} · Internal ${defenderInternal.length}${defenderOther.length > 0 ? ' · Other ' + defenderOther.length : ''}
                </div>`;

            const verdictBlock = `
                <div style="margin-bottom: 12px; padding: 10px 12px; border-left: 2px solid ${verdictColor}; background: var(--lb-bg);">
                    <div class="lb-strong" style="color: ${verdictColor}; font-size: 13px;">${escapeHtml(verdictLine)}</div>
                    ${breakdownLine}
                </div>`;

            // Show actual rows only when there's something interesting (threat
            // verdicts, or scan events with details). Internal Bm* state is
            // stashed behind a toggle.
            const interestingEvents = [...defenderThreats, ...defenderScans];
            const interestingTable = interestingEvents.length > 0
                ? `<table class="lb-table">
                    <thead><tr><th>Provider</th><th>Event</th><th>Scan Target</th><th>Verdict</th><th>Time</th></tr></thead>
                    <tbody>${renderDefenderRows(interestingEvents.slice(0, 50))}</tbody>
                  </table>
                  ${interestingEvents.length > 50 ? `<div class="lb-muted" style="font-size: 12px; padding: 6px 0; font-style: italic;">… and ${interestingEvents.length - 50} more</div>` : ''}`
                : '';

            const internalEvents = [...defenderInternal, ...defenderOther];
            const internalToggle = internalEvents.length > 0
                ? `<div style="margin-top: 12px; border-top: 1px dashed var(--lb-border); padding-top: 10px;">
                    <span id="defenderNoiseToggle" style="cursor: pointer; text-decoration: underline; color: var(--lb-text-dim); font-size: 12px;">
                        Show ${internalEvents.length} internal Defender event${internalEvents.length === 1 ? '' : 's'} (Bm* state plumbing)
                    </span>
                    <div id="defenderNoiseTable" class="hidden" style="margin-top: 8px;">
                        <table class="lb-table">
                            <thead><tr><th>Provider</th><th>Event</th><th>Scan Target</th><th>Verdict</th><th>Time</th></tr></thead>
                            <tbody>${renderDefenderRows(internalEvents.slice(0, 50))}</tbody>
                        </table>
                        ${internalEvents.length > 50 ? `<div class="lb-muted" style="font-size: 12px; padding: 6px 0; font-style: italic;">… and ${internalEvents.length - 50} more</div>` : ''}
                    </div>
                  </div>`
                : '';

            html += panel(
                hasThreatVerdict ? 'Defender — Threat Verdicts' : 'Defender',
                verdictBlock + interestingTable + internalToggle,
                headerBadge
            );
        }

        // Timeline
        if (timeline.length) {
            html += panel('Event Timeline', `
                <div style="display: flex; flex-direction: column;">
                    ${timeline.map(event => `
                        <div style="display: grid; grid-template-columns: 110px 130px 1fr; gap: 12px; padding: 6px 0; border-bottom: 1px dashed var(--lb-border); font-size: 12px;">
                            <span class="lb-mono lb-muted">${escapeHtml(formatEtwTime(event.time))}</span>
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
                                <td class="lb-mono lb-muted">${escapeHtml(formatEtwTime(c.time))}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `, String(cpuChanges.length));
        }

        // ETW Provider Diagnostics — collapsible, surfaces per-provider event
        // counts so it's obvious whether a 0 in (e.g.) network_activity means
        // "ETW didn't deliver any Kernel-Network events" or "events arrived
        // but my parser missed them". User-mode ETW often attributes outbound
        // TCP to System(4) or svchost, which RedEdr's filter drops — that
        // would show as Microsoft-Windows-Kernel-Network: 0 here even when
        // the payload made real network calls. Reliable capture needs
        // RedEdr's --hook mode (kernel driver path).
        const providerCounts = summary.events_by_provider || {};
        const providerEntries = Object.entries(providerCounts).sort((a, b) => b[1] - a[1]);
        if (providerEntries.length > 0) {
            const knownProviders = new Set([
                'Microsoft-Windows-Kernel-Process',
                'Microsoft-Windows-Kernel-File',
                'Microsoft-Windows-Kernel-Network',
                'Microsoft-Windows-Kernel-Audit-API-Calls',
                'Microsoft-Antimalware-Engine',
            ]);
            const missingProviders = [...knownProviders].filter(p => !(p in providerCounts));
            html += `
                <div class="lb-panel">
                    <div class="lb-panel-hdr">
                        <span class="lb-glyph">▸</span>ETW Provider Diagnostics
                        <span class="lb-panel-badge">${providerEntries.length} provider${providerEntries.length === 1 ? '' : 's'}</span>
                        <button id="rededrDiagToggle" class="lb-btn lb-btn-ghost" style="margin-left: auto; padding: 2px 10px; font-size: 12px;">Show</button>
                    </div>
                    <div id="rededrDiagBody" class="lb-panel-body hidden">
                        <p class="lb-muted" style="font-size: 12px; margin-bottom: 10px;">
                            Per-provider event counts. A subscribed provider with <code>0</code>
                            events usually means ETW delivered events but RedEdr filtered them
                            out (e.g. Kernel-Network often attributes outbound TCP to System
                            or svchost, not the payload PID). Reliable capture for those
                            categories requires RedEdr's <code>--hook</code> kernel-driver path.
                        </p>
                        <table class="lb-table">
                            <thead><tr><th>Provider</th><th>Events delivered</th></tr></thead>
                            <tbody>
                                ${providerEntries.map(([prov, count]) => `
                                    <tr>
                                        <td class="lb-mono">${escapeHtml(prov)}</td>
                                        <td class="lb-mono">${count}</td>
                                    </tr>
                                `).join('')}
                                ${missingProviders.map(prov => `
                                    <tr>
                                        <td class="lb-mono lb-muted">${escapeHtml(prov)}</td>
                                        <td class="lb-mono lb-muted">0 (no events received)</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>`;
        }

        // DLLs / Images / Threads / Network / File Ops / Audit API sub-tabs
        const tabBtn = (name, label, count, active) => {
            const baseStyle = 'padding: 8px 14px; background: transparent; border: 0; font-family: inherit; font-size: 13px; cursor: pointer;';
            const activeStyle = 'color: var(--lb-text); border-bottom: 2px solid var(--lb-accent-soft);';
            const inactiveStyle = 'color: var(--lb-text-dim); border-bottom: 2px solid transparent;';
            return `<button onclick="switchInnerTab('${name}')" class="tab-button${active ? ' active' : ''}" style="${baseStyle} ${active ? activeStyle : inactiveStyle}">${label} (${count})</button>`;
        };
        html += `
            <div class="lb-panel">
                <div style="display: flex; border-bottom: 1px solid var(--lb-border); flex-wrap: wrap;">
                    ${tabBtn('dlls', 'DLLs', loadedDlls.length, true)}
                    ${tabBtn('images', 'Images', imageLoads.length + imageUnloads.length, false)}
                    ${tabBtn('threads', 'Threads', threads.length, false)}
                    ${tabBtn('network', 'Network', networkActivity.length, false)}
                    ${tabBtn('fileops', 'File Ops', fileOps.length, false)}
                    ${tabBtn('auditapi', 'Audit API', auditApi.length, false)}
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
                            <button onclick="filterImages('loads')" class="lb-btn" style="padding: 4px 10px; font-size: 12px;">Loads (${imageLoads.length})</button>
                            <button onclick="filterImages('unloads')" class="lb-btn" style="padding: 4px 10px; font-size: 12px;">Unloads (${imageUnloads.length})</button>
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

                <div id="network-tab" class="tab-content hidden">
                    <div class="lb-panel-body">
                        ${networkActivity.length === 0
                            ? '<div class="lb-muted" style="padding: 8px 0; font-size: 12px;">No network activity observed.</div>'
                            : `<table class="lb-table">
                                <thead><tr><th>Proto</th><th>Local</th><th>Remote</th><th>Op</th><th>Size</th><th>Time</th></tr></thead>
                                <tbody>
                                    ${networkActivity.map(n => `
                                        <tr>
                                            <td class="lb-mono">${escapeHtml(n.proto || '?')}</td>
                                            <td class="lb-mono lb-muted">${escapeHtml(String(n.local_addr || '—'))}${n.local_port ? ':' + escapeHtml(String(n.local_port)) : ''}</td>
                                            <td class="lb-mono">${escapeHtml(String(n.remote_addr || '—'))}${n.remote_port ? ':' + escapeHtml(String(n.remote_port)) : ''}</td>
                                            <td class="lb-mono lb-muted">${escapeHtml(n.operation || '—')}</td>
                                            <td class="lb-mono lb-muted">${n.size != null ? formatBytes(Number(n.size) || 0) : '—'}</td>
                                            <td class="lb-mono lb-muted">${escapeHtml(formatEtwTime(n.time))}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>`}
                    </div>
                </div>

                <div id="fileops-tab" class="tab-content hidden">
                    <div class="lb-panel-body">
                        ${fileOps.length === 0
                            ? '<div class="lb-muted" style="padding: 8px 0; font-size: 12px;">No file operations observed.</div>'
                            : `<table class="lb-table">
                                <thead><tr><th>Path</th><th>Operation</th><th>Thread</th><th>Time</th></tr></thead>
                                <tbody>
                                    ${fileOps.map(f => `
                                        <tr>
                                            <td class="lb-mono" style="word-break: break-all;">${escapeHtml(String(f.path || '—'))}</td>
                                            <td class="lb-mono lb-muted">${escapeHtml(f.operation || '—')}</td>
                                            <td class="lb-mono lb-muted">${escapeHtml(String(f.thread_id ?? '—'))}</td>
                                            <td class="lb-mono lb-muted">${escapeHtml(formatEtwTime(f.time))}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>`}
                    </div>
                </div>

                <div id="auditapi-tab" class="tab-content hidden">
                    <div class="lb-panel-body">
                        ${auditApi.length === 0
                            ? '<div class="lb-muted" style="padding: 8px 0; font-size: 12px;">No audit-API calls observed.</div>'
                            : `<table class="lb-table">
                                <thead><tr><th>API</th><th>Target PID</th><th>Target TID</th><th>Caller PID/TID</th><th>Time</th></tr></thead>
                                <tbody>
                                    ${auditApi.map(a => `
                                        <tr>
                                            <td class="lb-mono">${escapeHtml(a.api || '—')}</td>
                                            <td class="lb-mono">${escapeHtml(String(a.target_pid ?? '—'))}</td>
                                            <td class="lb-mono lb-muted">${escapeHtml(String(a.target_tid ?? '—'))}</td>
                                            <td class="lb-mono lb-muted">${escapeHtml(String(a.caller_pid ?? '—'))} / ${escapeHtml(String(a.caller_tid ?? '—'))}</td>
                                            <td class="lb-mono lb-muted">${escapeHtml(formatEtwTime(a.time))}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>`}
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

        // Defender internal-events toggle — show/hide Bm* state plumbing.
        const noiseToggle = document.getElementById('defenderNoiseToggle');
        const noiseTable = document.getElementById('defenderNoiseTable');
        if (noiseToggle && noiseTable) {
            const internalCount = defenderInternal.length + defenderOther.length;
            noiseToggle.addEventListener('click', () => {
                const hidden = noiseTable.classList.toggle('hidden');
                noiseToggle.textContent = hidden
                    ? `Show ${internalCount} internal Defender event${internalCount === 1 ? '' : 's'} (Bm* state plumbing)`
                    : `Hide ${internalCount} internal Defender event${internalCount === 1 ? '' : 's'}`;
            });
        }

        // ETW provider diagnostic toggle.
        const diagToggle = document.getElementById('rededrDiagToggle');
        const diagBody = document.getElementById('rededrDiagBody');
        if (diagToggle && diagBody) {
            diagToggle.addEventListener('click', () => {
                const hidden = diagBody.classList.toggle('hidden');
                diagToggle.textContent = hidden ? 'Show' : 'Hide';
            });
        }
    },
};
