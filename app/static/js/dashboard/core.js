// app/static/js/dashboard/core.js
//
// Drives the index dashboard. Polls /api/system/scanners for analyzer
// availability and /api/edr/agents/status for live agent + Elastic state.
// Auto-refreshes every 60s; the manual Refresh button forces an immediate
// poll. Both fetches are kicked off in parallel.

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
    const scanners = (payload && payload.scanners) || [];
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
        const [scannersResp, agentsResp] = await Promise.all([
            fetch('/api/system/scanners', { cache: 'no-store' }),
            fetch('/api/edr/agents/status', { cache: 'no-store' }),
        ]);

        if (scannersResp.ok) {
            renderScanners(await scannersResp.json());
        } else {
            const host = document.getElementById('scannersTable');
            if (host) host.innerHTML =
                `<div class="lb-muted">Failed to load scanners (HTTP ${scannersResp.status}).</div>`;
        }

        if (agentsResp.ok) {
            const data = await agentsResp.json();
            for (const agent of (data.agents || [])) applyAgentRow(agent);
        }
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
// /api/system/scanners + /api/edr/agents/status every minute when nobody's
// looking. Resume on visible AND fire one immediate refresh so the user
// sees fresh data the moment they come back.
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
        stopTimer();
    } else {
        refreshDashboard();
        startTimer();
    }
});

window.addEventListener('beforeunload', stopTimer);
