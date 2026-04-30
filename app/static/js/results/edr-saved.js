// app/static/js/results/edr-saved.js
//
// Saved-view bootstrap for /results/edr/<profile>/<target>. We don't fetch
// or poll anything — the template embedded the full findings dict as
// `window.__edrSavedResults`. Hand it to the live tools/edr.js renderer so
// the saved view shows the *same* rich data (MITRE chips, call stack,
// triggering API, memory region, expandable per-alert detail, raw _source)
// as the standalone /analyze/edr/... page.

import edrModule from './tools/edr.js';

const data = window.__edrSavedResults;

document.addEventListener('DOMContentLoaded', () => {
    if (!data) {
        console.error('[edr-saved] window.__edrSavedResults is missing');
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
