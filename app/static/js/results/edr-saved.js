// app/static/js/results/edr-saved.js
//
// Saved-view bootstrap for /results/edr/<profile>/<target>. The page
// renders a static shell; we lazy-fetch the JSON via the existing
// `/api/results/edr/<profile>/<target>` endpoint on DOMContentLoaded
// and hand it to the same tools/edr.js renderer the live page uses
// (so the saved view shows MITRE chips, call stack, expandable per-
// alert detail, raw _source — same renderer, no fork).
//
// The earlier shape inlined the entire findings dict via `{{ ... | tojson }}`
// in the template, which on alert-heavy runs blew up the HTML and
// slowed TTFB. Lazy-fetching keeps the initial HTML small and lets the
// browser cache the JSON between reloads.

import edrModule from './tools/edr.js';

document.addEventListener('DOMContentLoaded', async () => {
    const ref = window.__edrSavedRef;
    if (!ref || !ref.profile || !ref.target) {
        console.error('[edr-saved] window.__edrSavedRef is missing or incomplete');
        return;
    }

    const url = `/api/results/edr/${encodeURIComponent(ref.profile)}/${encodeURIComponent(ref.target)}`;
    let data;
    try {
        const resp = await fetch(url, { cache: 'no-store' });
        if (!resp.ok) {
            console.error(`[edr-saved] ${url} returned HTTP ${resp.status}`);
            return;
        }
        data = await resp.json();
    } catch (err) {
        console.error(`[edr-saved] fetch failed:`, err);
        return;
    }

    // The renderer's lazy DOM lookup tolerates missing IDs, so passing a
    // best-effort `element` here is enough — renderSummary / renderAlerts /
    // renderExecution each find their own targets internally.
    edrModule.render(data, {
        element: document.getElementById('edrAlertsResults'),
        statsElement: document.getElementById('edrAlertsStats'),
    });
});
