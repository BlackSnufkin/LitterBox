// app/static/js/byovd/api.js
// Caching/abort-aware fetch wrapper for the BYOVD info page.

import { PERF_CONFIG } from './utils.js';

// ===== PERFORMANCE-OPTIMIZED API CLIENT =====
export class APIClient {
  constructor() {
    this.cache = new Map();
    this.abortController = null;
  }

  async fetch(url, options = {}) {
    const cacheKey = `${url}_${JSON.stringify(options)}`;
    
    // Check cache first
    if (!options.forceRefresh && this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      if (performance.now() - cached.timestamp < PERF_CONFIG.CACHE_TTL) {
        return cached.data;
      }
      this.cache.delete(cacheKey);
    }

    // Cancel previous request
    if (this.abortController) {
      this.abortController.abort();
    }
    this.abortController = new AbortController();

    try {
      const response = await fetch(url, {
        ...options,
        signal: this.abortController.signal,
        cache: options.forceRefresh ? 'no-cache' : 'no-store'
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      
      // Cache successful responses
      this.cache.set(cacheKey, {
        data,
        timestamp: performance.now()
      });

      return data;
    } catch (error) {
      if (error.name !== 'AbortError') {
        throw error;
      }
    }
  }

  clearCache() {
    this.cache.clear();
  }

  destroy() {
    if (this.abortController) {
      this.abortController.abort();
    }
    this.clearCache();
  }
}

