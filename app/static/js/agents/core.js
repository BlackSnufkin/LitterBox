// app/static/js/agents/core.js
//
// Drives the /agents inventory page. Hits /api/edr/agents/status to probe
// each registered EDR profile in parallel (server-side ThreadPool), then
// fills the per-card status fields. Refreshes every 15s; the manual
// Refresh button forces an immediate poll.

const REFRESH_MS = 60000;
let _refreshTimer = null;
let _inFlight = false;

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function setColor(id, color) {
    const el = document.getElementById(id);
    if (el) el.style.color = color;
}

function setDot(profile, kind /* 'ok' | 'down' | 'partial' | 'unknown' */, title) {
    const el = document.getElementById(`agentDot-${profile}`);
    if (!el) return;
    el.className = `lb-agent-dot lb-agent-dot--${kind}`;
    if (title) el.title = title;
}

function applyStatus(agent) {
    const p = agent.name;

    // Type badge — for now everything is `elastic-defend`, but the field
    // is server-driven so future agent types render automatically.
    setText(`agentType-${p}`, agent.type || 'unknown');

    const a = agent.agent || {};
    const e = agent.elastic || {};
    // Fibratus profiles have no Elastic backend — alerts arrive via the
    // /api/edr/fibratus/ingest push endpoint. Health = agent reachable.
    const isFibratus = agent.kind === 'fibratus';

    if (isFibratus) {
        setDot(p, a.reachable ? 'ok' : 'down',
               a.reachable ? 'Agent reachable (Fibratus push model)' : 'Agent unreachable');
    } else {
        // Aggregate dot: green if both sides reachable, yellow if only one,
        // red if neither.
        const reachable = (a.reachable ? 1 : 0) + (e.reachable ? 1 : 0);
        if (reachable === 2)      setDot(p, 'ok', 'Agent + Elastic reachable');
        else if (reachable === 1) setDot(p, 'partial', 'Partial — see status fields');
        else                       setDot(p, 'down', 'Agent + Elastic unreachable');
    }

    // Agent side
    if (a.reachable) {
        setText(`agentStatus-${p}`, 'Online');
        setColor(`agentStatus-${p}`, 'var(--lb-sev-low)');
        setText(`agentHostname-${p}`, a.hostname || '—');
        setText(`agentOs-${p}`,       a.os_version || '—');
        setText(`agentVersion-${p}`,  a.agent_version || '—');
    } else {
        setText(`agentStatus-${p}`, 'Offline');
        setColor(`agentStatus-${p}`, 'var(--lb-accent-soft)');
        setText(`agentHostname-${p}`, '—');
        setText(`agentOs-${p}`,       '—');
        setText(`agentVersion-${p}`,  '—');
    }

    // Lock
    if (agent.lock) {
        const inUse = !!agent.lock.in_use;
        setText(`agentLock-${p}`, inUse ? 'Busy (run in progress)' : 'Idle');
        setColor(`agentLock-${p}`, inUse ? 'var(--lb-sev-medium)' : 'var(--lb-sev-low)');
    } else {
        setText(`agentLock-${p}`, '—');
        setColor(`agentLock-${p}`, 'var(--lb-text-mute)');
    }

    // Backend side. Elastic profiles: probe the cluster. Fibratus
    // profiles: no remote backend — show the push-buffer label.
    if (isFibratus) {
        setText(`agentElastic-${p}`, 'Push-mode (no remote backend)');
        setColor(`agentElastic-${p}`, 'var(--lb-text-mute)');
        setText(`agentCluster-${p}`, '—');
    } else if (e.reachable) {
        const v = e.version ? ` v${e.version}` : '';
        setText(`agentElastic-${p}`, `Reachable${v}`);
        setColor(`agentElastic-${p}`, 'var(--lb-sev-low)');
        setText(`agentCluster-${p}`, e.cluster_name || '—');
    } else {
        setText(`agentElastic-${p}`, 'Unreachable');
        setColor(`agentElastic-${p}`, 'var(--lb-accent-soft)');
        setText(`agentCluster-${p}`, '—');
    }

    // Combined error block (shows if anything failed)
    const errEl = document.getElementById(`agentError-${p}`);
    if (errEl) {
        const errs = [];
        if (a.error) errs.push(`Agent: ${a.error}`);
        if (e.error) errs.push(`Elastic: ${e.error}`);
        if (errs.length) {
            errEl.textContent = errs.join('  ·  ');
            errEl.classList.remove('hidden');
        } else {
            errEl.classList.add('hidden');
        }
    }
}

async function refreshAgents() {
    if (_inFlight) return;
    _inFlight = true;
    const btn = document.getElementById('agentsRefreshBtn');
    if (btn) btn.disabled = true;

    try {
        const resp = await fetch('/api/edr/agents/status', { cache: 'no-store' });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        for (const agent of (data.agents || [])) applyStatus(agent);
    } catch (err) {
        console.error('[agents] refresh failed:', err);
    } finally {
        _inFlight = false;
        if (btn) btn.disabled = false;
    }
}

// Expose for the inline onclick on the Refresh button.
window.refreshAgents = refreshAgents;

function startAgentsTimer() {
    if (_refreshTimer != null) return;
    _refreshTimer = setInterval(refreshAgents, REFRESH_MS);
}
function stopAgentsTimer() {
    if (_refreshTimer != null) {
        clearInterval(_refreshTimer);
        _refreshTimer = null;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    refreshAgents();
    startAgentsTimer();
});

// Pause polling when the tab is hidden; on resume fire one immediate
// refresh so the page shows fresh data the moment the operator looks
// back at it.
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
        stopAgentsTimer();
    } else {
        refreshAgents();
        startAgentsTimer();
    }
});

window.addEventListener('beforeunload', () => {
    if (_refreshTimer) clearInterval(_refreshTimer);
});
