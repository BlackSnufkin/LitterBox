// app/static/js/results/tools/edr.js
//
// Renderer for an Elastic-EDR run dispatched to a Whiskers agent.
//
// The orchestrator runs in two phases:
//   Phase 1 (exec)        — sync over HTTP; returns when the agent finishes
//                          spawning the payload (success or EDR block)
//   Phase 2 (correlation) — async on the server (background thread);
//                          polls Elastic for alerts, overwrites the saved
//                          findings JSON when done.
//
// On the initial POST response we render whatever Phase 1 produced. If
// the status is `polling_alerts`, we kick off a foreground poll of GET
// /api/results/edr/<profile>/<hash> so the alerts pane and summary chip
// reflect Phase 2 progress in real time. The block-vs-clean-exec
// distinction is carried in `summary.blocked_by_av` — Phase 2 doesn't
// fork its status on it because the polling itself is purely between
// LitterBox and Elastic, regardless of what the EDR VM did.
//
// Targets:
//   - #edrSummary           (summary tab)
//   - #edrAlertsResults     (alerts tab table + stat strip)
//   - #edrExecutionResults  (execution tab stdout/stderr block)
//   - top-of-page status bar — we flip "Analysis completed" back to
//     "Correlating Elastic alerts…" while polling.

import { errorPanel, cleanState, threatState, statRow, panel, kvGrid, codeBlock, tag, escapeHtml } from './_shared.js';
import summaryTool from './summary.js';

const HIGH_SEVERITY = new Set(['high', 'critical']);
const POLLING_STATUS = 'polling_alerts';
const POLL_INTERVAL_MS = 3000;

// Module-level handle so a re-render with a new payload aborts the old
// poll loop (defensive — only one EDR result per page in practice).
let _pollTimer = null;

function clearPoll() {
    if (_pollTimer != null) {
        clearTimeout(_pollTimer);
        _pollTimer = null;
    }
}

function isPolling(results) {
    return results?.status === POLLING_STATUS;
}

function severityRank(s) {
    return ({ critical: 4, high: 3, medium: 2, low: 1 })[String(s || '').toLowerCase()] || 0;
}

function severityTagClass(s) {
    const sev = String(s || '').toLowerCase();
    if (sev === 'critical' || sev === 'high') return 'critical';
    if (sev === 'medium') return 'medium';
    if (sev === 'low') return 'info';
    return 'muted';
}

function fmtDate(iso) {
    if (!iso) return '—';
    try {
        const d = new Date(iso);
        if (Number.isNaN(d.getTime())) return iso;
        return d.toLocaleString();
    } catch {
        return iso;
    }
}

function renderSummary(results) {
    const target = document.getElementById('edrSummary');
    if (!target) return;

    const profile     = results.display_name || results.profile || 'EDR Profile';
    const agent       = results.agent_info || {};
    const summary     = results.summary || {};
    const exec        = results.execution || {};
    const status      = results.status || 'unknown';
    const hostname    = results.hostname || agent.hostname || '—';

    const pairs = [
        ['Profile',        profile,                                  false],
        ['Status',         status],
        ['Agent Hostname', hostname],
        ['Agent Version',  agent.agent_version || '—'],
        ['OS Version',     agent.os_version || '—',                  false],
        ['PID',            exec.pid != null ? String(exec.pid) : '—'],
        ['Run Started',    fmtDate(summary.run_start),               false],
        ['Run Ended',      fmtDate(summary.run_end),                 false],
    ];

    target.innerHTML = kvGrid(pairs, 2);
}

function renderAlerts(results) {
    const target = document.getElementById('edrAlertsResults');
    const stats  = document.getElementById('edrAlertsStats');
    if (!target) return;

    const alerts = Array.isArray(results.alerts) ? results.alerts : [];
    const summary = results.summary || {};
    const status  = results.status || 'unknown';

    // Stat strip
    const totalAlerts   = summary.total_alerts != null ? summary.total_alerts : alerts.length;
    const highSevCount  = summary.high_severity_alerts != null
        ? summary.high_severity_alerts
        : alerts.filter(a => HIGH_SEVERITY.has(String(a.severity || '').toLowerCase())).length;

    // Map the orchestrator's machine status onto a short, human label so
    // the stat chip stays the same width as the numeric ones beside it.
    const STATUS_LABELS = {
        'completed':                'Completed',
        'blocked_by_av':            'EDR Block',
        'polling_alerts':           'Polling…',
        'partial':                  'Partial',
        'busy':                     'Busy',
        'agent_unreachable':        'Offline',
        'error':                    'Error',
    };
    const statusLabel = STATUS_LABELS[status] || status;
    const statusSeverity = (
        status === 'completed' && totalAlerts === 0 ? 'clean' :
        status === 'completed' ? 'critical' :
        status === 'blocked_by_av' ? 'critical' :
        status === 'polling_alerts' ? 'info' :
        status === 'partial' ? 'medium' :
        'critical'
    );

    if (stats) {
        stats.innerHTML = statRow([
            { label: 'Status',   value: statusLabel,   severity: statusSeverity },
            { label: 'Alerts',   value: totalAlerts,   severity: totalAlerts > 0 ? 'critical' : 'clean' },
            { label: 'Critical', value: highSevCount,  severity: highSevCount > 0 ? 'critical' : 'clean' },
            { label: 'Window',   value: summary.wait_seconds_for_alerts != null
                                              ? `${summary.wait_seconds_for_alerts}s`
                                              : '—',
                                 severity: 'info' },
        ]);
    }

    // Body
    if (status === 'agent_unreachable') {
        target.innerHTML = errorPanel('Whiskers agent unreachable', { error: results.error, agent_url: results.agent_url });
        return;
    }

    if (status === 'partial') {
        target.innerHTML = errorPanel(
            `Run completed but Elastic query failed (${results.sub_status || 'unknown'})`,
            { error: results.error }
        );
        return;
    }

    if (isPolling(results)) {
        // Phase 2 in flight on the server — show a busy indicator in the
        // alerts pane until the next poll updates this state.
        const max = summary.wait_seconds_for_alerts || '?';
        const blockedHint = summary.blocked_by_av
            ? ' The EDR blocked the spawn; we are correlating against the prevention alert.'
            : '';
        target.innerHTML = `
            <div class="lb-empty" style="flex-direction: column; padding: 24px 16px; gap: 8px; align-items: flex-start;">
                <div style="display:flex; align-items:center; gap:10px;">
                    <svg width="16" height="16" fill="none" stroke="var(--lb-accent-soft)" viewBox="0 0 24 24" class="animate-spin" style="animation: lb-spin 1s linear infinite;">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                    </svg>
                    <span class="lb-strong">Correlating Elastic alerts…</span>
                </div>
                <span class="lb-muted" style="font-size: 12px;">Polling every ${POLL_INTERVAL_MS / 1000}s, max ${max}s window.${blockedHint}</span>
            </div>
            <style>@keyframes lb-spin { to { transform: rotate(360deg); } }</style>`;
        return;
    }

    if (status === 'blocked_by_av' && alerts.length === 0) {
        target.innerHTML = threatState(
            'Blocked by AV before execution',
            results.execution?.message || 'The local AV intercepted the payload before it ran. No post-run alerts to correlate.'
        );
        return;
    }

    if (alerts.length === 0) {
        target.innerHTML = cleanState(
            'No alerts raised',
            `${profileLabel(results)} did not raise alerts during the ${summary.wait_seconds_for_alerts || '?'}s correlation window.`
        );
        return;
    }

    // Sort by severity desc, then detection time desc.
    const sorted = [...alerts].sort((a, b) => {
        const d = severityRank(b.severity) - severityRank(a.severity);
        if (d !== 0) return d;
        return String(b.detected_at || '').localeCompare(String(a.detected_at || ''));
    });

    const rows = sorted.map((a, i) => renderAlertRow(a, i)).join('');

    target.innerHTML = `
        <table class="lb-table lb-edr-alerts">
            <thead><tr>
                <th style="width:42px;"></th>
                <th>Severity</th>
                <th>Rule</th>
                <th>Process</th>
                <th>Trigger</th>
                <th>Detected</th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>`;

    // Wire expand/collapse — one click handler delegated to the table.
    target.querySelector('table').addEventListener('click', (ev) => {
        const expander = ev.target.closest('.lb-edr-expand');
        if (!expander) return;
        const idx = expander.dataset.idx;
        const detail = target.querySelector(`tr.lb-edr-detail[data-idx="${idx}"]`);
        if (!detail) return;
        const isOpen = detail.classList.toggle('open');
        expander.textContent = isOpen ? '▾' : '▸';
    });
}

function renderAlertRow(a, idx) {
    const d = a.details || {};
    const sevClass = severityTagClass(a.severity);
    const sevText  = String(a.severity || 'unknown').toUpperCase();
    const proc = d.process || {};
    const procCell = proc.name
        ? `${escapeHtml(proc.name)}${proc.pid != null ? ` <span class="lb-muted">(${proc.pid})</span>` : ''}`
        : '—';
    const trigger = (() => {
        if (d.api && d.api.name) {
            return `<span class="lb-mono" style="font-size: 12px; color: var(--lb-accent-soft);">${escapeHtml(d.api.summary || d.api.name + '()')}</span>`;
        }
        const responseAction = (d.responses || []).find(r => r.action);
        if (responseAction) {
            const tag = responseAction.tree ? `${responseAction.action} (tree)` : responseAction.action;
            return `<span class="lb-tag critical">${escapeHtml(tag)}</span>`;
        }
        return '<span class="lb-muted">—</span>';
    })();
    return `
        <tr class="lb-edr-row">
            <td><button type="button" class="lb-edr-expand" data-idx="${idx}" aria-label="Expand"
                style="background:none;border:0;color:var(--lb-text-mute);cursor:pointer;font-size: 13px;padding:0 4px;">▸</button></td>
            <td>${tag(sevClass, sevText)}</td>
            <td class="lb-strong" style="font-size: 13px;">${escapeHtml(a.title || 'Unknown alert')}</td>
            <td class="lb-mono" style="font-size: 12px;">${procCell}</td>
            <td>${trigger}</td>
            <td class="lb-muted" style="font-size: 12px; white-space: nowrap;">${escapeHtml(fmtDate(a.detected_at))}</td>
        </tr>
        <tr class="lb-edr-detail" data-idx="${idx}">
            <td colspan="6">${renderAlertDetail(a)}</td>
        </tr>`;
}

function renderAlertDetail(a) {
    const d = a.details || {};
    const sections = [];

    // Reason — the kibana-formatted one-liner if present.
    if (d.reason) {
        sections.push(`
            <div class="lb-edr-section">
                <span class="lb-eyebrow">Reason</span>
                <div class="lb-edr-reason"><div>${escapeHtml(d.reason)}</div></div>
            </div>`);
    }

    // Rule description — shown inline right after the reason, since the
    // reason is *what fired the rule* and the description is *what the
    // rule means*. Keeping these together makes the alert self-explanatory
    // without requiring a click to expand.
    if (d.rule_description) {
        const refs = (d.rule_references || []).slice(0, 5);
        const refList = refs.length
            ? `<div style="margin-top: 8px; display: flex; flex-direction: column; gap: 4px; font-size: 11px;">
                 <span class="lb-muted">References:</span>
                 ${refs.map(r => `<a href="${escapeHtml(r)}" target="_blank" rel="noopener" class="lb-mono" style="word-break: break-all;">${escapeHtml(r)}</a>`).join('')}
               </div>`
            : '';
        sections.push(`
            <div class="lb-edr-section">
                <span class="lb-eyebrow">Rule Description</span>
                <div style="font-size: 12px; color: var(--lb-text-dim); white-space: pre-wrap;">${escapeHtml(d.rule_description)}</div>
                ${refList}
            </div>`);
    }

    // MITRE — chips with links.
    if (d.mitre && d.mitre.length) {
        const chips = d.mitre.map(m => {
            const techText = `${m.technique_id || ''} ${m.technique_name || ''}`.trim() || 'Technique';
            const tacticText = m.tactic_name ? `${m.tactic_id || ''} ${m.tactic_name}`.trim() : 'Tactic';
            const subText = m.subtechnique_name ? `${m.subtechnique_id || ''} ${m.subtechnique_name}`.trim() : null;
            return `
                <div class="lb-edr-mitre-row">
                    <a class="lb-edr-chip lb-edr-chip--tactic" href="${escapeHtml(m.tactic_reference || '#')}" target="_blank" rel="noopener">${escapeHtml(tacticText)}</a>
                    <span class="lb-muted">›</span>
                    <a class="lb-edr-chip lb-edr-chip--tech" href="${escapeHtml(m.technique_reference || '#')}" target="_blank" rel="noopener">${escapeHtml(techText)}</a>
                    ${subText ? `<span class="lb-muted">›</span><a class="lb-edr-chip lb-edr-chip--sub" href="${escapeHtml(m.subtechnique_reference || '#')}" target="_blank" rel="noopener">${escapeHtml(subText)}</a>` : ''}
                </div>`;
        }).join('');
        sections.push(`<div class="lb-edr-section"><span class="lb-eyebrow">MITRE ATT&CK</span>${chips}</div>`);
    }

    // API trigger.
    if (d.api && d.api.name) {
        const behaviors = (d.api.behaviors || []).map(b => `<span class="lb-tag info">${escapeHtml(b)}</span>`).join(' ');
        sections.push(`
            <div class="lb-edr-section">
                <span class="lb-eyebrow">Triggering API</span>
                <div class="lb-mono lb-strong" style="font-size: 14px; color: var(--lb-accent-soft);">${escapeHtml(d.api.summary || d.api.name + '()')}</div>
                ${behaviors ? `<div style="margin-top:6px; display:flex; gap:6px; flex-wrap:wrap;">${behaviors}</div>` : ''}
                ${(d.api.metadata && Object.keys(d.api.metadata).length)
                    ? `<pre class="lb-mono lb-edr-pre">${escapeHtml(JSON.stringify(d.api.metadata, null, 2))}</pre>`
                    : ''}
            </div>`);
    }

    // Memory region — only when populated.
    if (d.memory_region && (d.memory_region.region_protection || d.memory_region.mapped_path)) {
        const m = d.memory_region;
        sections.push(`
            <div class="lb-edr-section">
                <span class="lb-eyebrow">Memory Region</span>
                ${kvGrid([
                    ['Allocation Protection', m.allocation_protection || '—'],
                    ['Current Protection',    m.region_protection || '—'],
                    ['Region State',          m.region_state || '—', false],
                    ['Allocation Type',       m.allocation_type || '—', false],
                    ['Region Size',           m.region_size != null ? `${m.region_size} bytes` : '—'],
                    ['Allocation Size',       m.allocation_size != null ? `${m.allocation_size} bytes` : '—'],
                    ['Mapped Path',           m.mapped_path || '—', false],
                ], 2)}
            </div>`);
    }

    // Call stack.
    if (d.call_stack && d.call_stack.length) {
        const summary = d.call_stack_summary
            ? `<div class="lb-mono lb-edr-stack-summary">${escapeHtml(d.call_stack_summary)}</div>`
            : '';
        const frames = d.call_stack.map((f, i) => renderStackFrame(f, i, d.call_stack_final_user_module)).join('');
        sections.push(`
            <div class="lb-edr-section">
                <span class="lb-eyebrow">Call Stack <span class="lb-muted" style="text-transform:none;">(top is where the monitor fired)</span></span>
                ${summary}
                <div class="lb-edr-stack">${frames}</div>
            </div>`);
    }

    // Final user module — the suspicious one. Defend uses two literal
    // sentinel strings when it couldn't resolve a module:
    //   "Undetermined" — kernel-bridge call with no user-mode module
    //                    identified (often callback abuse)
    //   "Unbacked"     — code lives in private allocation with no file
    //                    backing (classic shellcode / injected payload)
    // Both are STRONGER signals than a normal module name; we render an
    // explanation instead of a half-empty grid in those cases.
    if (d.call_stack_final_user_module) {
        const m = d.call_stack_final_user_module;
        const isUnresolved = (m.name === 'Undetermined' || m.name === 'Unbacked');
        const explanation = m.name === 'Unbacked'
            ? 'Code is in private memory with no file backing — classic shellcode / runtime-injected payload. There is no module on disk to hash or verify.'
            : m.name === 'Undetermined'
            ? "Elastic Defend couldn't resolve a user-mode module for the closest caller — the call entered the kernel from runtime-allocated code, often a callback-abuse pattern. No mapped image means no path, hash, or code signature to report."
            : null;

        const sigStatus = m.code_signature
            ? (m.code_signature.exists === false ? 'unsigned' : (m.code_signature.subject_name || m.code_signature.status || 'signed'))
            : '—';

        // Only show populated rows. A grid full of dashes communicates
        // nothing useful and made the section read as "broken".
        const allPairs = [
            ['Module',           m.name],
            ['Path',             m.path],
            ['SHA256',           m.sha256],
            ['Code Signature',   m.code_signature ? sigStatus : null],
            ['Provenance',       m.protection_provenance],
            ['Provenance Path',  m.protection_provenance_path],
            ['Allocation Bytes', m.allocation_private_bytes != null ? String(m.allocation_private_bytes) : null],
        ];
        const populated = allPairs
            .filter(([, v]) => v != null && v !== '')
            .map(([k, v]) => [k, v, k === 'Module' || k === 'Path' || k === 'Code Signature' || k === 'Provenance' || k === 'Provenance Path' ? false : undefined]);

        sections.push(`
            <div class="lb-edr-section lb-edr-section--accent">
                <span class="lb-eyebrow">Final User Module <span class="lb-muted" style="text-transform:none;">(closest user-mode caller)</span></span>
                ${explanation ? `<div style="font-size: 12px; color: var(--lb-accent-soft); margin-bottom: 4px;">${escapeHtml(explanation)}</div>` : ''}
                ${populated.length ? kvGrid(populated, 2) : ''}
                ${isUnresolved && populated.length === 1 ? '' : ''}
            </div>`);
    }

    // Process card.
    if (d.process) {
        const p = d.process;
        const sigStatus = p.code_signature
            ? (p.code_signature.exists === false ? 'unsigned' : (p.code_signature.subject_name || p.code_signature.status || 'signed'))
            : '—';
        sections.push(`
            <div class="lb-edr-section">
                <span class="lb-eyebrow">Process</span>
                ${kvGrid([
                    ['Name',         p.name || '—',         false],
                    ['PID',          p.pid != null ? String(p.pid) : '—'],
                    ['Executable',   p.executable || '—',   false],
                    ['Command Line', p.command_line || '—', false],
                    ['Working Dir',  p.working_directory || '—', false],
                    ['Integrity',    p.integrity_level || '—', false],
                    ['SHA256',       p.sha256 || '—'],
                    ['imphash',      p.imphash || '—'],
                    ['Code Sig',     sigStatus, false],
                    ['Entity ID',    p.entity_id || '—'],
                ], 2)}
            </div>`);
    }

    // Parent.
    if (d.parent && (d.parent.name || d.parent.executable)) {
        const p = d.parent;
        sections.push(`
            <div class="lb-edr-section">
                <span class="lb-eyebrow">Parent Process</span>
                ${kvGrid([
                    ['Name',         p.name || '—',         false],
                    ['PID',          p.pid != null ? String(p.pid) : '—'],
                    ['Executable',   p.executable || '—',   false],
                    ['Command Line', p.command_line || '—', false],
                ], 2)}
            </div>`);
    }

    // Defend response — what was killed/isolated/etc.
    if (d.responses && d.responses.length) {
        const rows = d.responses.map(r => {
            const ok = r.result === 0;
            return `<tr>
                <td><span class="lb-tag ${ok ? 'critical' : 'medium'}">${escapeHtml(r.action || '—')}${r.tree ? ' · tree' : ''}</span></td>
                <td class="lb-mono" style="font-size: 12px;">${escapeHtml(r.target_name || '—')}</td>
                <td class="lb-mono" style="font-size: 12px;">${r.target_pid != null ? r.target_pid : '—'}</td>
                <td class="lb-muted" style="font-size: 12px;">${escapeHtml(r.result_message || '—')}</td>
            </tr>`;
        }).join('');
        sections.push(`
            <div class="lb-edr-section">
                <span class="lb-eyebrow">EDR Response</span>
                <table class="lb-table" style="margin-top:6px;">
                    <thead><tr><th>Action</th><th>Target Process</th><th>PID</th><th>Result</th></tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>`);
    }

    // User + tags.
    const meta = [];
    if (d.user && (d.user.name || d.user.domain)) {
        meta.push(`<span class="lb-edr-meta-pill">User: ${escapeHtml((d.user.domain ? d.user.domain + '\\\\' : '') + (d.user.name || ''))}</span>`);
    }
    if (d.event_action) {
        meta.push(`<span class="lb-edr-meta-pill">event.action: ${escapeHtml(Array.isArray(d.event_action) ? d.event_action.join(', ') : d.event_action)}</span>`);
    }
    if (d.risk_score != null) {
        meta.push(`<span class="lb-edr-meta-pill">risk_score: ${escapeHtml(String(d.risk_score))}</span>`);
    }
    if (d.rule_tags && d.rule_tags.length) {
        for (const t of d.rule_tags.slice(0, 6)) {
            meta.push(`<span class="lb-edr-meta-pill lb-edr-meta-pill--tag">${escapeHtml(t)}</span>`);
        }
    }
    if (meta.length) {
        sections.push(`
            <div class="lb-edr-section">
                <span class="lb-eyebrow">Metadata</span>
                <div class="lb-edr-meta">${meta.join('')}</div>
            </div>`);
    }

    // Raw _source (collapsed).
    if (a.raw) {
        sections.push(`
            <details class="lb-edr-section">
                <summary class="lb-eyebrow" style="cursor:pointer;">Raw _source</summary>
                <pre class="lb-mono lb-edr-pre">${escapeHtml(JSON.stringify(a.raw, null, 2))}</pre>
            </details>`);
    }

    return `<div class="lb-edr-detail-body">${sections.join('')}</div>`;
}

function renderStackFrame(f, idx, finalModule) {
    const isFinal = finalModule && finalModule.name && f.module && finalModule.name.toLowerCase() === f.module.toLowerCase();
    const isUnknown = !f.module || f.symbol_info === 'Unknown';
    const klass = isUnknown ? 'lb-edr-frame--unknown' : (f.provenance ? 'lb-edr-frame--provenance' : (isFinal ? 'lb-edr-frame--final' : ''));
    const moduleHtml = isUnknown
        ? '<span class="lb-mono lb-edr-frame-mod" style="color:var(--lb-accent);">UNKNOWN</span>'
        : `<span class="lb-mono lb-edr-frame-mod">${escapeHtml(f.module || '—')}</span>`;
    const fnHtml = f.function
        ? `<span class="lb-mono lb-muted">!${escapeHtml(f.function)}</span>`
        : '';
    const offHtml = f.offset
        ? `<span class="lb-mono lb-muted">+${escapeHtml(f.offset)}</span>`
        : '';
    const provHtml = f.provenance
        ? `<span class="lb-edr-frame-prov">provenance: <span class="lb-mono">${escapeHtml(f.provenance)}</span></span>`
        : '';
    return `
        <div class="lb-edr-frame ${klass}">
            <span class="lb-edr-frame-idx">${idx}</span>
            ${moduleHtml}${fnHtml}${offHtml}
            ${provHtml}
        </div>`;
}

function renderExecution(results) {
    const target = document.getElementById('edrExecutionResults');
    if (!target) return;

    const exec = results.execution || {};
    const status = exec.exec_status || results.status || 'unknown';
    const killedByEdr = !!exec.killed_by_edr;

    // When the EDR's behavior protection killed the process, label it
    // distinctly. The agent always reports "exited" because Windows can't
    // tell the parent the kill came from outside; the orchestrator
    // synthesizes this label by cross-referencing the prevention alerts.
    const statusDisplay = killedByEdr
        ? 'killed by EDR behavior protection'
        : status;

    const meta = kvGrid([
        ['PID',          exec.pid != null ? String(exec.pid) : '—'],
        ['Exit Code',    exec.exit_code != null ? String(exec.exit_code) : '—'],
        ['Status',       statusDisplay],
        ['Hostname',     results.hostname || '—',  false],
    ], 2);

    const badge = (
        results.status === 'blocked_by_av' ? 'AV BLOCK' :
        killedByEdr ? 'EDR KILL' :
        null
    );

    let body = panel('Run Metadata', meta, badge);

    if (killedByEdr) {
        body += panel(
            'Behavior Protection Verdict',
            `<div class="lb-strong" style="color: var(--lb-accent); font-size: 13px;">Process terminated by EDR behavior protection.</div>
             <div class="lb-muted" style="font-size: 12px; margin-top: 4px;">The EDR raised a prevention-class alert during the run window and the process exited with a non-zero code. See the Alerts tab for the matching detection.</div>`
        );
    }

    if (exec.message) {
        body += panel('Agent Message', `<div class="lb-muted" style="font-size: 13px;">${escapeHtml(exec.message)}</div>`,
                      results.status === 'blocked_by_av' ? 'AV BLOCK' : null);
    }

    if (exec.stdout) {
        body += panel('Standard Output', codeBlock(exec.stdout, { label: 'stdout' }));
    } else {
        body += panel('Standard Output', `<div class="lb-muted" style="font-size: 12px;">(empty)</div>`);
    }

    if (exec.stderr) {
        body += panel('Standard Error', codeBlock(exec.stderr, { label: 'stderr', color: 'var(--lb-accent-soft)' }));
    }

    target.innerHTML = body;
}

function profileLabel(results) {
    return results.display_name || results.profile || 'EDR profile';
}

function fileHashFromPath() {
    // /analyze/edr/<profile>/<hash> — the hash is the last segment.
    const parts = window.location.pathname.split('/').filter(Boolean);
    return parts[parts.length - 1];
}

function schedulePoll(profile) {
    clearPoll();
    const hash = fileHashFromPath();
    if (!hash || !profile) return;
    _pollTimer = setTimeout(async () => {
        try {
            const resp = await fetch(`/api/results/edr/${encodeURIComponent(profile)}/${encodeURIComponent(hash)}`, {
                cache: 'no-store',
            });
            if (!resp.ok) {
                // 404 during polling is unusual but not fatal — keep trying.
                schedulePoll(profile);
                return;
            }
            const updated = await resp.json();
            // Re-render the EDR-specific panes (Alerts, Execution).
            const ctx = { element: document.getElementById('edrAlertsResults') };
            edrModule.render(updated, ctx);
            // Re-render the Summary tab too — the scanner table row
            // should reflect the new alert count, and Process Output
            // should pick up any newly-arrived stdout/stderr. Calling
            // summaryTool.render with `{edr: updated}` is correct for
            // EDR-only runs (no other tools contribute to summary in
            // this flow).
            const summaryStats = document.getElementById('scannerResultsBody');
            if (summaryStats) {
                summaryTool.render({ edr: updated }, {
                    element: summaryStats,
                    statsElement: summaryStats,
                });
            }
        } catch (err) {
            console.error('[edr] poll failed:', err);
            schedulePoll(profile);
        }
    }, POLL_INTERVAL_MS);
}

/**
 * Reflect Phase-2 polling status in the page-level status bar so the
 * operator doesn't see a misleading "Analysis completed" while the
 * background poll is still running. Also keeps/stops the duration timer
 * so the chip ticks through Phase 2 and freezes at the moment Phase 2
 * actually wraps up — not at the moment Phase 1 returns.
 */
function updatePageStatus(polling) {
    const statusEl = document.getElementById('analysisStatus');
    const iconEl   = document.getElementById('statusIcon');
    const core     = window.__analysisCore;
    if (!statusEl) return;
    if (polling) {
        statusEl.textContent = 'Correlating Elastic alerts…';
        if (iconEl) {
            iconEl.innerHTML = `
                <svg class="animate-spin" width="20" height="20" fill="none" stroke="var(--lb-accent-soft)" viewBox="0 0 24 24" style="animation: lb-spin 1s linear infinite;">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>`;
        }
    } else {
        statusEl.textContent = 'Analysis completed';
        if (iconEl) {
            iconEl.innerHTML = `
                <svg width="20" height="20" fill="none" stroke="var(--lb-sev-low)" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                </svg>`;
        }
        // Phase 2 done — freeze the duration chip at its current value.
        if (core) {
            try { core.updateTimer(); core.stopTimer(); core.updateStageToComplete?.(); }
            catch (e) { console.error('[edr] could not finalize timer:', e); }
        }
    }
}


const edrModule = {
    id: 'edr',
    elementId: 'edrAlertsResults',
    statsElementId: 'edrAlertsStats',

    render(results, _ctx) {
        if (!results) return;

        // Always render summary + execution panes — they convey what we
        // know (profile, agent identity, error message) regardless of
        // whether the run reached Elastic. The alerts pane gets the
        // error panel for hard-error cases.
        renderSummary(results);
        renderExecution(results);

        if (results.status === 'error') {
            clearPoll();
            const target = document.getElementById('edrAlertsResults');
            if (target) target.innerHTML = errorPanel(
                results.error || 'EDR analysis failed',
                { profile: results.profile }
            );
            updatePageStatus(false);
            return;
        }

        renderAlerts(results);

        if (isPolling(results)) {
            schedulePoll(results.profile);
            updatePageStatus(true);
        } else {
            clearPoll();
            updatePageStatus(false);
        }
    },
};

export default edrModule;
