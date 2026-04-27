// app/static/js/utils/escape.js
// XSS-safe HTML escaping. Promote in F4–F7 when render functions
// interpolate user-controlled data into innerHTML / template literals.

const HTML_ESCAPE_MAP = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
    '`': '&#x60;',
    '=': '&#x3D;',
};

const HTML_ESCAPE_RE = /[&<>"'`=\/]/g;

export function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    return String(text).replace(HTML_ESCAPE_RE, (ch) => HTML_ESCAPE_MAP[ch]);
}

// Tagged template helper:  html`<div>${userInput}</div>`
// Auto-escapes interpolated values; leaves the static string parts untouched.
export function html(strings, ...values) {
    let out = '';
    strings.forEach((str, i) => {
        out += str;
        if (i < values.length) {
            const v = values[i];
            out += (v && v.__safe === true) ? v.value : escapeHtml(v);
        }
    });
    return out;
}

// Mark a string as already-safe so html`...` will not re-escape it.
export function safe(value) {
    return { __safe: true, value: String(value) };
}
