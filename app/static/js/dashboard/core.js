// app/static/js/dashboard/core.js
//
// Drives the index dashboard. Single /health fetch returns scanner
// inventory + live EDR agent reachability in one shot. Auto-refreshes
// every 60s; the manual Refresh button forces an immediate poll.

const REFRESH_MS = 60000;
let _refreshTimer = null;
let _inFlight = false;

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

// ---- Scanners -----------------------------------------------------------
function statusTagClass(status) {
    return (
        status === 'ok'       ? 'low' :
        status === 'missing'  ? 'high' :
        status === 'disabled' ? 'muted' :
                                'muted'
    );
}

function renderScanners(payload) {
    const host = document.getElementById('scannersTable');
    if (!host) return;
    const scanners = (payload && payload.rows) || [];
    const counts = (payload && payload.counts) || {};
    setText('scannersCount',
        `${counts.ok ?? 0} ok · ${counts.missing ?? 0} missing · ${counts.disabled ?? 0} disabled`);

    if (!scanners.length) {
        host.innerHTML = '<div class="lb-muted" style="font-size: 12px;">No analyzers configured.</div>';
        return;
    }

    // Group by `group` (static / dynamic / holygrail), preserving config order.
    const groups = new Map();
    for (const s of scanners) {
        if (!groups.has(s.group)) groups.set(s.group, []);
        groups.get(s.group).push(s);
    }

    const parts = [];
    for (const [group, rows] of groups) {
        parts.push(`<div class="lb-scanner-group-hdr">${escapeHtml(group)}</div>`);
        for (const r of rows) {
            const tag = statusTagClass(r.status);
            parts.push(`
                <div class="lb-scanner-row" title="${escapeHtml(r.tool_path || '')}">
                    <span class="lb-strong">${escapeHtml(capitalize(r.name))}</span>
                    <span class="lb-scanner-path">${escapeHtml(r.tool_path || '—')}</span>
                    <span class="lb-tag ${tag}">${escapeHtml(r.status)}</span>
                </div>
            `);
        }
    }
    host.innerHTML = parts.join('');
}

// ---- Agents -------------------------------------------------------------
function setDot(profile, kind, title) {
    const el = document.getElementById(`dashAgentDot-${profile}`);
    if (!el) return;
    el.className = `lb-agent-dot lb-agent-dot--${kind}`;
    if (title) el.title = title;
}

function setTag(id, kind, text) {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = `lb-tag ${kind}`;
    el.textContent = text;
}

function applyAgentRow(agent) {
    const p = agent.name;
    const a = agent.agent || {};
    const e = agent.elastic || {};
    // Fibratus profiles have no Elastic backend — alerts arrive via the
    // /api/edr/fibratus/ingest push endpoint. Treat agent-up alone as healthy.
    const isFibratus = agent.kind === 'fibratus';

    if (isFibratus) {
        setDot(p, a.reachable ? 'ok' : 'down',
               a.reachable ? 'Agent reachable (Fibratus push)' : 'Agent unreachable');
    } else {
        const reachable = (a.reachable ? 1 : 0) + (e.reachable ? 1 : 0);
        if (reachable === 2)      setDot(p, 'ok',      'Agent + Elastic reachable');
        else if (reachable === 1) setDot(p, 'partial', 'Partial — see status fields');
        else                       setDot(p, 'down',    'Agent + Elastic unreachable');
    }

    if (a.reachable) {
        const v = a.agent_version ? ` v${a.agent_version}` : '';
        setTag(`dashAgentSide-${p}`, 'low', `agent${v}`);
    } else {
        setTag(`dashAgentSide-${p}`, 'high', 'agent down');
    }

    if (isFibratus) {
        setTag(`dashElasticSide-${p}`, 'info', 'fibratus · push');
    } else if (e.reachable) {
        const v = e.version ? ` v${e.version}` : '';
        setTag(`dashElasticSide-${p}`, 'low', `elastic${v}`);
    } else {
        setTag(`dashElasticSide-${p}`, 'high', 'elastic down');
    }
}

// ---- Drive --------------------------------------------------------------
async function refreshDashboard() {
    if (_inFlight) return;
    _inFlight = true;
    const btn = document.getElementById('dashRefreshBtn');
    if (btn) btn.disabled = true;

    try {
        // Single /health fetch returns both scanner inventory and EDR
        // reachability. /health responds 200 (ok) or 503 (degraded) — both
        // carry a usable payload, so we read JSON either way.
        const resp = await fetch('/health', { cache: 'no-store' });
        if (resp.status !== 200 && resp.status !== 503) {
            const host = document.getElementById('scannersTable');
            if (host) host.innerHTML =
                `<div class="lb-muted">Failed to load health (HTTP ${resp.status}).</div>`;
            return;
        }

        const data = await resp.json();
        renderScanners(data.scanners || {});
        for (const agent of ((data.edr_agents || {}).agents || [])) applyAgentRow(agent);
    } catch (err) {
        console.error('[dashboard] refresh failed:', err);
    } finally {
        _inFlight = false;
        if (btn) btn.disabled = false;
    }
}

function capitalize(s) {
    const str = String(s ?? '');
    return str ? str[0].toUpperCase() + str.slice(1) : '';
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => (
        { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
}

window.refreshDashboard = refreshDashboard;

function startTimer() {
    if (_refreshTimer != null) return;
    _refreshTimer = setInterval(refreshDashboard, REFRESH_MS);
}

function stopTimer() {
    if (_refreshTimer != null) {
        clearInterval(_refreshTimer);
        _refreshTimer = null;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    refreshDashboard();
    startTimer();
});

// Pause the auto-refresh while the tab is hidden — no point pulling
// /health every minute when nobody's looking. Resume on visible AND fire
// one immediate refresh so the user sees fresh data the moment they come back.
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
        stopTimer();
    } else {
        refreshDashboard();
        startTimer();
    }
});

window.addEventListener('beforeunload', stopTimer);
