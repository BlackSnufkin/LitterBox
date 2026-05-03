// app/static/js/analyze-all/core.js
//
// Coordinator for the "All" pipeline.
//
// Concurrency model:
//   - Static and EDR (every profile) start immediately, in parallel.
//   - Dynamic waits for Static to finish (NOT EDR — EDR runs on a separate
//     VM and has no resource contention with the local Dynamic analyzers).
//     EDR continues in parallel with Dynamic.
//   - The page redirects to /results/info/<hash> when *all three* settle.
//
// Each row gets a live status dot (queued / running / done / failed) and
// an elapsed counter. Static failure still allows Dynamic to start (the
// operator decides if a static-fail run is worth observing dynamically).

const cfg = window.__allRunCfg || { fileHash: '', edrProfiles: [] };
const PAGE_START = Date.now();
const POST_HEADERS = { 'Content-Type': 'application/json' };

// Args carried over from the upload page (shared between dynamic + EDR runs).
function loadArgs() {
    try {
        const raw = localStorage.getItem('analysisArgs');
        return raw ? JSON.parse(raw) : [];
    } catch {
        return [];
    }
}
const ARGS = loadArgs();

function row(stage, profile = null) {
    const sel = profile
        ? `.lb-all-row[data-stage="${stage}"][data-profile="${profile}"]`
        : `.lb-all-row[data-stage="${stage}"]`;
    return document.querySelector(sel);
}

// Map row kind → human label + lb-tag severity class for the state pill.
const STATE_LABEL = {
    queued:  { label: 'QUEUED',    cls: 'muted' },
    running: { label: 'RUNNING',   cls: 'medium' },
    done:    { label: 'COMPLETED', cls: 'low' },
    failed:  { label: 'FAILED',    cls: 'high' },
    skipped: { label: 'SKIPPED',   cls: 'muted' },
};

function setStatus(stage, profile, kind, detailText) {
    const r = row(stage, profile);
    if (!r) return;
    const dot    = r.querySelector('[data-role="dot"]');
    const detail = r.querySelector('[data-role="detail"]');
    const state  = r.querySelector('[data-role="state"]');
    if (dot) dot.className = `lb-all-dot lb-all-dot--${kind}`;
    if (detail && detailText != null) detail.textContent = detailText;
    if (state) {
        const meta = STATE_LABEL[kind] || STATE_LABEL.queued;
        state.className = `lb-tag ${meta.cls} lb-all-state`;
        state.textContent = meta.label;
    }
    r.classList.toggle('is-skipped', kind === 'skipped');
    refreshStagesCounter();
}

// Refresh the "N / total" stages counter at the top of the page based on
// how many rows are in a terminal state (done / failed / skipped).
function refreshStagesCounter() {
    const counter = document.getElementById('allStagesCounter');
    if (!counter) return;
    const rows = document.querySelectorAll('.lb-all-row');
    let total = rows.length;
    let settled = 0;
    rows.forEach(r => {
        const dot = r.querySelector('[data-role="dot"]');
        if (!dot) return;
        if (dot.classList.contains('lb-all-dot--done') ||
            dot.classList.contains('lb-all-dot--failed') ||
            dot.classList.contains('lb-all-dot--skipped')) {
            settled += 1;
        }
    });
    counter.textContent = `${settled} / ${total}`;
}

// Track total EDR alerts seen across all profiles, surface in the top tile.
let _totalAlerts = 0;
function bumpAlertCounter(n) {
    _totalAlerts += n;
    const el = document.getElementById('allAlertsCounter');
    if (el) {
        el.textContent = String(_totalAlerts);
        el.style.color = _totalAlerts > 0 ? 'var(--lb-accent-soft)' : '';
    }
}
function setAlertCounter(n) {
    _totalAlerts = n;
    const el = document.getElementById('allAlertsCounter');
    if (el) {
        el.textContent = String(_totalAlerts);
        el.style.color = _totalAlerts > 0 ? 'var(--lb-accent-soft)' : '';
    }
}
setAlertCounter(0);

function setElapsed(stage, profile, ms) {
    const r = row(stage, profile);
    if (!r) return;
    const el = r.querySelector('[data-role="elapsed"]');
    if (!el) return;
    if (ms == null) { el.textContent = '—'; return; }
    const s = Math.floor(ms / 1000);
    el.textContent = `${Math.floor(s / 60).toString().padStart(2, '0')}:${(s % 60).toString().padStart(2, '0')}`;
}

// Top-of-page overall timer. Runs from page load until all done.
// Mirrors into both the badge in the title bar AND the big tile at the
// top of the page (which gets sub-second updates via the same interval).
const overallEl    = document.getElementById('allOverallTimer');
const elapsedTileEl = document.getElementById('allElapsedDisplay');
function fmtElapsed(ms) {
    const s = Math.floor(ms / 1000);
    return `${Math.floor(s / 60).toString().padStart(2, '0')}:${(s % 60).toString().padStart(2, '0')}`;
}
let overallTimer = setInterval(() => {
    const text = fmtElapsed(Date.now() - PAGE_START);
    if (overallEl)     overallEl.textContent = text;
    if (elapsedTileEl) elapsedTileEl.textContent = text;
}, 1000);

// Per-row live elapsed ticker — only running rows tick.
const tickers = new Map();
function startTicker(stage, profile = null) {
    const key = `${stage}|${profile || ''}`;
    const t0 = Date.now();
    const id = setInterval(() => setElapsed(stage, profile, Date.now() - t0), 500);
    tickers.set(key, { id, t0 });
}
function stopTicker(stage, profile = null) {
    const key = `${stage}|${profile || ''}`;
    const t = tickers.get(key);
    if (t) {
        clearInterval(t.id);
        setElapsed(stage, profile, Date.now() - t.t0);
        tickers.delete(key);
    }
}

// ---- Static -------------------------------------------------------------
async function runStatic() {
    setStatus('static', null, 'running', 'Running static analyzers…');
    startTicker('static');
    try {
        const resp = await fetch(`/analyze/static/${cfg.fileHash}`, {
            method: 'POST', headers: POST_HEADERS, body: JSON.stringify({}),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok || data.status === 'error') {
            setStatus('static', null, 'failed', `Failed: ${data.error || ('HTTP ' + resp.status)}`);
        } else {
            setStatus('static', null, 'done', 'Completed');
        }
    } catch (err) {
        setStatus('static', null, 'failed', `Error: ${err.message}`);
    } finally {
        stopTicker('static');
    }
}

// ---- EDR (per profile) --------------------------------------------------
//
// `/analyze/edr/<profile>/<hash>` POST returns Phase 1 immediately (status =
// "polling_alerts"). Phase 2 runs in a daemon thread on the server and
// overwrites the saved JSON when alerts settle. The coordinator polls the
// saved JSON until status is no longer "polling_alerts".
async function runEdrProfile(profile) {
    setStatus('edr', profile, 'running', 'Phase 1: agent dispatch…');
    startTicker('edr', profile);
    try {
        const resp = await fetch(`/analyze/edr/${encodeURIComponent(profile)}/${cfg.fileHash}`, {
            method: 'POST', headers: POST_HEADERS, body: JSON.stringify({ args: ARGS }),
        });
        const data = await resp.json().catch(() => ({}));
        const phase1 = (data.results && data.results.edr) || data;

        if (resp.status === 502 || phase1.status === 'agent_unreachable') {
            setStatus('edr', profile, 'failed', 'Whiskers agent unreachable');
            return;
        }
        if (resp.status === 409 || phase1.status === 'busy') {
            setStatus('edr', profile, 'failed', 'Agent busy with another run');
            return;
        }
        if (phase1.status === 'error') {
            setStatus('edr', profile, 'failed', `Phase 1 failed: ${phase1.error || 'unknown'}`);
            return;
        }

        // Phase 1 ok — poll for Phase 2 completion.
        setStatus('edr', profile, 'running', 'Phase 2: correlating Elastic alerts…');
        const final = await pollEdr(profile);
        if (!final) {
            setStatus('edr', profile, 'failed', 'Phase 2 timed out');
            return;
        }
        const totalAlerts = (final.summary || {}).total_alerts ?? (final.alerts || []).length;
        const blocked = (final.summary || {}).blocked_by_av;
        const killed  = (final.execution || {}).killed_by_edr;
        const detail  = (
            blocked            ? `EDR blocked the spawn` :
            killed             ? `Killed by EDR · ${totalAlerts} alert${totalAlerts === 1 ? '' : 's'}` :
            totalAlerts > 0    ? `${totalAlerts} alert${totalAlerts === 1 ? '' : 's'} raised` :
                                 'No alerts raised'
        );
        const failed = (final.status === 'partial' || final.status === 'error');
        setStatus('edr', profile, failed ? 'failed' : 'done', failed ? `${final.status}: ${final.error || ''}` : detail);
        if (!failed && totalAlerts > 0) bumpAlertCounter(totalAlerts);
    } catch (err) {
        setStatus('edr', profile, 'failed', `Error: ${err.message}`);
    } finally {
        stopTicker('edr', profile);
    }
}

async function pollEdr(profile, intervalMs = 3000, maxMs = 180000) {
    const deadline = Date.now() + maxMs;
    while (Date.now() < deadline) {
        await new Promise(r => setTimeout(r, intervalMs));
        try {
            const resp = await fetch(
                `/api/results/edr/${encodeURIComponent(profile)}/${cfg.fileHash}`,
                { cache: 'no-store' },
            );
            if (!resp.ok) continue;
            const data = await resp.json();
            if (data.status && data.status !== 'polling_alerts') return data;
        } catch { /* keep polling */ }
    }
    return null;
}

// ---- Dynamic ------------------------------------------------------------
async function runDynamic() {
    setStatus('dynamic', null, 'running', 'Spawning payload + driving local analyzers…');
    startTicker('dynamic');
    try {
        const resp = await fetch(`/analyze/dynamic/${cfg.fileHash}`, {
            method: 'POST', headers: POST_HEADERS, body: JSON.stringify({ args: ARGS }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok || data.status === 'error') {
            setStatus('dynamic', null, 'failed', `Failed: ${data.error || ('HTTP ' + resp.status)}`);
            return;
        }
        if (data.status === 'early_termination') {
            setStatus('dynamic', null, 'failed', `Early termination: ${data.error || ''}`);
            return;
        }
        setStatus('dynamic', null, 'done', 'Completed');
    } catch (err) {
        setStatus('dynamic', null, 'failed', `Error: ${err.message}`);
    } finally {
        stopTicker('dynamic');
    }
}

// ---- Agent preflight ----------------------------------------------------
//
// Hit /api/edr/agents/status (server-cached, ~instant) before kicking off
// the EDR profiles. Profiles whose agent isn't reachable get marked as
// "skipped" with no dispatch attempt — saves the 4-5s timeout each agent
// would otherwise burn just to fail.
async function probeReachableProfiles() {
    if (!cfg.edrProfiles.length) return new Set();
    try {
        const resp = await fetch('/api/edr/agents/status', { cache: 'no-store' });
        if (!resp.ok) return null;     // soft-fail → caller dispatches all
        const data = await resp.json();
        const byName = new Map(
            (data.agents || []).map(a => [a.name, !!(a.agent && a.agent.reachable)])
        );
        const reachable = new Set();
        for (const p of cfg.edrProfiles) {
            // Profiles we don't have status for get the benefit of the
            // doubt — let the dispatch attempt surface the real error.
            if (!byName.has(p) || byName.get(p)) reachable.add(p);
        }
        return reachable;
    } catch {
        return null;     // soft-fail
    }
}

// ---- Orchestration ------------------------------------------------------
async function run() {
    // Preflight EDR agents — skip the ones the dashboard says are down.
    const reachable = await probeReachableProfiles();
    const edrToDispatch = [];
    for (const p of cfg.edrProfiles) {
        if (reachable === null || reachable.has(p)) {
            edrToDispatch.push(p);
        } else {
            setStatus('edr', p, 'skipped', 'Agent unreachable — skipped');
        }
    }

    // Static + reachable EDR profiles fire immediately, all in parallel.
    const staticPromise = runStatic();
    const edrPromises = edrToDispatch.map(p => runEdrProfile(p));

    // Dynamic waits ONLY for Static — EDR is on a remote VM, no resource
    // contention with the local Dynamic analyzers. EDR continues in
    // parallel with Dynamic.
    const dynamicPromise = (async () => {
        await staticPromise.catch(() => {});  // proceed even if Static failed
        setStatus('dynamic', null, 'queued', 'Static finished — starting');
        await runDynamic();
    })();

    // Wait for everything to settle.
    await Promise.allSettled([staticPromise, ...edrPromises, dynamicPromise]);

    clearInterval(overallTimer);
    // Don't auto-redirect — the operator wants to see the full data for
    // each scan, not the slim file-info summary. Make each row clickable
    // to its detailed saved view instead.
    linkifyCompletedRows();
    showDoneBanner();
}

/** Once the pipeline settles, mark each completed row as clickable so
 *  it links to its saved detailed view. Failed / skipped rows stay
 *  non-interactive. The arrow chevron is built into the template and
 *  the `.is-clickable` class controls its visibility (CSS). */
function linkifyCompletedRows() {
    document.querySelectorAll('.lb-all-row').forEach(r => {
        const dot = r.querySelector('[data-role="dot"]');
        if (!dot || !dot.classList.contains('lb-all-dot--done')) return;
        const stage = r.dataset.stage;
        const profile = r.dataset.profile;
        const url = (
            stage === 'static'  ? `/results/static/${cfg.fileHash}` :
            stage === 'dynamic' ? `/results/dynamic/${cfg.fileHash}` :
            stage === 'edr'     ? `/results/edr/${encodeURIComponent(profile)}/${cfg.fileHash}` :
                                  null
        );
        if (!url) return;
        r.classList.add('is-clickable');
        r.title = `View saved ${stage} results`;
        r.addEventListener('click', () => { window.location.href = url; });
    });
}

function showDoneBanner() {
    const banner = document.getElementById('allDoneBanner');
    if (!banner) return;
    banner.classList.remove('hidden');

    // Populate the jump-row with one link per stage that actually
    // produced saved data — skip failed / skipped EDR profiles since
    // they don't have a saved view to navigate to.
    const jumpRow = banner.querySelector('.lb-all-jump-row');
    if (!jumpRow || jumpRow.children.length) return;

    const links = [];
    if (rowState('static') === 'done') {
        links.push(['Static', `/results/static/${cfg.fileHash}`, 'low']);
    }
    for (const p of cfg.edrProfiles) {
        if (rowState('edr', p) === 'done') {
            const profLabel = document.querySelector(
                `.lb-all-row[data-stage="edr"][data-profile="${p}"] .lb-strong`
            )?.textContent || p;
            links.push([profLabel, `/results/edr/${encodeURIComponent(p)}/${cfg.fileHash}`, 'low']);
        }
    }
    if (rowState('dynamic') === 'done') {
        links.push(['Dynamic', `/results/dynamic/${cfg.fileHash}`, 'low']);
    }
    links.push(['File Info', `/results/info/${cfg.fileHash}`, 'muted']);

    for (const [label, url, sev] of links) {
        const a = document.createElement('a');
        a.href = url;
        a.className = `lb-btn lb-btn-ghost lb-tag-${sev}`;
        a.textContent = label;
        jumpRow.appendChild(a);
    }
}

/** Read the terminal state of a row. Returns 'done' | 'failed' |
 *  'skipped' | 'queued' | 'running' based on the dot class. */
function rowState(stage, profile = null) {
    const r = row(stage, profile);
    const dot = r?.querySelector('[data-role="dot"]');
    if (!dot) return 'queued';
    for (const cls of ['done', 'failed', 'skipped', 'running', 'queued']) {
        if (dot.classList.contains(`lb-all-dot--${cls}`)) return cls;
    }
    return 'queued';
}

document.addEventListener('DOMContentLoaded', run);
