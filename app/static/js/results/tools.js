// app/static/js/results/tools.js
//
// Thin registry. Each scanner's renderer lives in its own module under
// tools/ and defines:
//
//   export default {
//       id:               'mytool',          // results.<id> key
//       elementId:        'myToolResults',   // primary DOM target
//       statsElementId?:  'myToolStats',     // optional stats target
//       render(results, ctx) { ... }         // ctx: { element, statsElement }
//   };
//
// To add a new scanner:
//   1. Create app/static/js/results/tools/<name>.js exporting the shape above
//   2. Import + add it to the `modules` array below
//   3. Make sure the result page template has the matching DOM IDs
//
// That's it — core.js iterates through `tools` and calls render() per result key.

import yaraTool          from './tools/yara.js';
import checkplzTool      from './tools/checkplz.js';
import stringnalyzerTool from './tools/stringnalyzer.js';
import peSieveTool       from './tools/pe_sieve.js';
import monetaTool        from './tools/moneta.js';
import patriotTool       from './tools/patriot.js';
import hsbTool           from './tools/hsb.js';
import rededrTool        from './tools/rededr.js';
import summaryTool       from './tools/summary.js';

const modules = [
    yaraTool,
    checkplzTool,
    stringnalyzerTool,
    peSieveTool,
    monetaTool,
    patriotTool,
    hsbTool,
    rededrTool,
    summaryTool,
];

/**
 * Build the public {tools} registry. Each entry exposes:
 *   - element:      DOM target (lazy — looked up at render time, so missing
 *                   tabs on a particular page don't break import).
 *   - statsElement: optional secondary DOM target.
 *   - render(results): wraps the module's render(results, ctx).
 *
 * Lazy element lookup also means a module survives being loaded before its
 * tab markup exists; render() returns silently if the element isn't there.
 */
export const tools = Object.fromEntries(modules.map(mod => {
    const entry = {
        get element()      { return document.getElementById(mod.elementId); },
        get statsElement() { return mod.statsElementId ? document.getElementById(mod.statsElementId) : null; },
        render(results) {
            const ctx = { element: entry.element, statsElement: entry.statsElement };
            if (!ctx.element) {
                // Tab not rendered on this page — silently skip.
                return;
            }
            mod.render(results, ctx);
        },
    };
    return [mod.id, entry];
}));
