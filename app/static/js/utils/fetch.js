// app/static/js/utils/fetch.js
// Thin wrapper around fetch() with consistent JSON parsing and error shape.
// Replaces 5+ inconsistent inline try/fetch/catch blocks across the codebase.

class HttpError extends Error {
    constructor(message, status, data) {
        super(message);
        this.name = 'HttpError';
        this.status = status;
        this.data = data;
    }
}

async function parseError(response) {
    const fallback = `HTTP ${response.status}`;
    try {
        const data = await response.json();
        return new HttpError(data.error || data.message || fallback, response.status, data);
    } catch (_) {
        return new HttpError(fallback, response.status, null);
    }
}

export async function apiGet(url, options = {}) {
    const response = await fetch(url, { method: 'GET', ...options });
    if (!response.ok) throw await parseError(response);
    return response.json();
}

export async function apiPost(url, body = null, options = {}) {
    const isFormData = (typeof FormData !== 'undefined') && (body instanceof FormData);
    const headers = { ...(options.headers || {}) };
    if (!isFormData && body !== null) {
        headers['Content-Type'] = headers['Content-Type'] || 'application/json';
    }
    const response = await fetch(url, {
        method: 'POST',
        headers,
        body: isFormData ? body : (body === null ? undefined : JSON.stringify(body)),
        ...options,
        // Re-apply headers after spread so caller-supplied options.headers can't get lost.
    });
    if (!response.ok) throw await parseError(response);
    return response.json();
}

export async function apiDelete(url, options = {}) {
    const response = await fetch(url, { method: 'DELETE', ...options });
    if (!response.ok) throw await parseError(response);
    return response.json();
}

// Cached GET — useful for relatively-static endpoints (e.g. /api/results/info/<hash>).
// Returns the cached promise on repeat calls; pass {forceRefresh:true} to bypass.
const _cache = new Map();
export async function apiGetCached(url, { forceRefresh = false, ...options } = {}) {
    if (!forceRefresh && _cache.has(url)) return _cache.get(url);
    const promise = apiGet(url, options).catch((err) => {
        _cache.delete(url);
        throw err;
    });
    _cache.set(url, promise);
    return promise;
}

export function clearApiCache(url) {
    if (url) _cache.delete(url);
    else _cache.clear();
}

export { HttpError };
