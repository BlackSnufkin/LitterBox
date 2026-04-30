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

function setStatus(stage, profile, kind, detailText) {
    const r = row(stage, profile);
    if (!r) return;
    const dot = r.querySelector('[data-role="dot"]');
    const detail = r.querySelector('[data-role="detail"]');
    if (dot) dot.className = `lb-all-dot lb-all-dot--${kind}`;
    if (detail && detailText != null) detail.textContent = detailText;
}

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
const overallEl = document.getElementById('allOverallTimer');
let overallTimer = setInterval(() => {
    const elapsed = Date.now() - PAGE_START;
    const s = Math.floor(elapsed / 1000);
    if (overallEl) overallEl.textContent =
        `${Math.floor(s / 60).toString().padStart(2, '0')}:${(s % 60).toString().padStart(2, '0')}`;
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

// ---- Orchestration ------------------------------------------------------
async function run() {
    // Static + every EDR profile fire immediately, all in parallel.
    const staticPromise = runStatic();
    const edrPromises = cfg.edrProfiles.map(p => runEdrProfile(p));

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

/** Once the pipeline settles, turn each row into a link to its saved
 *  detailed view (e.g. /results/static/<hash>, /results/dynamic/<hash>,
 *  /results/edr/<profile>/<hash>). Failed rows stay un-linked. */
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
        r.style.cursor = 'pointer';
        r.title = `View saved ${stage} results`;
        r.addEventListener('click', () => { window.location.href = url; });
        // Visual cue — drop a small chevron at the right edge.
        const arrow = document.createElement('span');
        arrow.className = 'lb-muted lb-mono';
        arrow.style.cssText = 'margin-left: 8px; font-size: 13px;';
        arrow.textContent = '→';
        r.appendChild(arrow);
    });
}

function showDoneBanner() {
    const banner = document.getElementById('allDoneBanner');
    if (!banner) return;
    banner.classList.remove('hidden');
    banner.querySelector('.lb-strong').textContent =
        'Pipeline complete — click any completed row to view its detailed results.';
    banner.querySelector('.lb-muted').textContent = '';
    // Add explicit jump buttons.
    const body = banner.querySelector('.lb-panel-body');
    if (body && !body.querySelector('.lb-all-jump-row')) {
        const div = document.createElement('div');
        div.className = 'lb-all-jump-row';
        div.style.cssText = 'display: flex; gap: 8px; justify-content: center; margin-top: 12px; flex-wrap: wrap;';
        const links = [
            ['Static',  `/results/static/${cfg.fileHash}`],
            ...cfg.edrProfiles.map(p => [p, `/results/edr/${encodeURIComponent(p)}/${cfg.fileHash}`]),
            ['Dynamic', `/results/dynamic/${cfg.fileHash}`],
            ['File Info', `/results/info/${cfg.fileHash}`],
        ];
        for (const [label, url] of links) {
            const a = document.createElement('a');
            a.href = url;
            a.className = 'lb-btn lb-btn-ghost';
            a.style.cssText = 'padding: 4px 12px; font-size: 12px;';
            a.textContent = label;
            div.appendChild(a);
        }
        body.appendChild(div);
    }
}

document.addEventListener('DOMContentLoaded', run);
