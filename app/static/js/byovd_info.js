// app/static/js/byovd_info.js - Ultra-Performance Optimized Complete Version
'use strict';

// ===== PERFORMANCE CONSTANTS =====
const PERF_CONFIG = {
  CACHE_TTL: 300000, // 5 minutes
  ANIMATION_DURATION: 800,
  FRAME_BUDGET: 16, // 16ms for 60fps
  BATCH_SIZE: 50,
  DEBOUNCE_DELAY: 100
};

// ===== MEMORY-EFFICIENT ELEMENT CACHE =====
class ElementCache {
  constructor() {
    this.cache = new Map();
    this.observer = null;
    this.setupMutationObserver();
  }

  get(selector) {
    if (!this.cache.has(selector)) {
      const element = document.querySelector(selector);
      if (element) {
        this.cache.set(selector, element);
      }
    }
    return this.cache.get(selector);
  }

  set(selector, element) {
    this.cache.set(selector, element);
  }

  clear() {
    this.cache.clear();
  }

  setupMutationObserver() {
    this.observer = new MutationObserver((mutations) => {
      let shouldClear = false;
      
      for (const mutation of mutations) {
        if (mutation.type === 'childList' && mutation.removedNodes.length > 0) {
          shouldClear = true;
          break;
        }
      }
      
      if (shouldClear) {
        this.cache.clear();
      }
    });
    
    if (document.body) {
      this.observer.observe(document.body, {
        childList: true,
        subtree: true
      });
    }
  }

  destroy() {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
    this.clear();
  }
}

// ===== HIGH-PERFORMANCE DOM UTILITIES =====
class DOMUtils {
  static FRAME_BUDGET = 16; // 16ms per frame for 60fps
  static operationQueue = [];
  static isProcessing = false;

  static batchUpdate(operations) {
    // Add operations to queue
    this.operationQueue.push(...operations);
    
    // Start processing if not already running
    if (!this.isProcessing) {
      this.processQueue();
    }
  }

  static processQueue() {
    if (this.operationQueue.length === 0) {
      this.isProcessing = false;
      return;
    }

    this.isProcessing = true;
    const startTime = performance.now();

    // Process operations within frame budget
    while (this.operationQueue.length > 0 && (performance.now() - startTime) < this.FRAME_BUDGET) {
      const operation = this.operationQueue.shift();
      try {
        operation();
      } catch (error) {
        console.warn('[BYOVD] Operation failed:', error);
      }
    }

    // Continue in next frame if more operations remain
    if (this.operationQueue.length > 0) {
      requestAnimationFrame(() => this.processQueue());
    } else {
      this.isProcessing = false;
    }
  }

  // Immediate update for critical operations (bypasses queue)
  static immediateUpdate(operations) {
    operations.forEach(op => {
      try {
        op();
      } catch (error) {
        console.warn('[BYOVD] Immediate operation failed:', error);
      }
    });
  }

  static setTextContent(element, text) {
    if (element && element.textContent !== text) {
      element.textContent = text;
    }
  }

  static setHTML(element, html) {
    if (element && element.innerHTML !== html) {
      element.innerHTML = html;
    }
  }

  static addClass(element, className) {
    if (element && !element.classList.contains(className)) {
      element.classList.add(className);
    }
  }

  static removeClass(element, className) {
    if (element && element.classList.contains(className)) {
      element.classList.remove(className);
    }
  }

  // Optimized for large HTML updates
  static setHTMLOptimized(element, html) {
    if (!element) return;
    
    // Use DocumentFragment for large updates
    const template = document.createElement('template');
    template.innerHTML = html;
    
    // Clear and append in single operation
    element.innerHTML = '';
    element.appendChild(template.content);
  }

  static createFromTemplate(templateId, data = {}) {
    const template = document.getElementById(templateId);
    if (!template) return null;
    
    const clone = template.content.cloneNode(true);
    
    // Replace placeholders efficiently
    Object.entries(data).forEach(([key, value]) => {
      const elements = clone.querySelectorAll(`[data-placeholder="${key}"]`);
      elements.forEach(el => {
        el.textContent = value;
      });
    });
    
    return clone;
  }
}

// ===== PERFORMANCE-OPTIMIZED API CLIENT =====
class APIClient {
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

// ===== OPTIMIZED ANIMATION SYSTEM =====
class AnimationSystem {
  static animateNumber(element, start, end, duration = PERF_CONFIG.ANIMATION_DURATION) {
    if (!element) return Promise.resolve();
    
    return new Promise((resolve) => {
      const startTime = performance.now();
      
      const animate = (currentTime) => {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Use easeOutCubic for smooth animation
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + (end - start) * easeOut);
        
        DOMUtils.setTextContent(element, current.toString());
        
        if (progress < 1) {
          requestAnimationFrame(animate);
        } else {
          resolve();
        }
      };
      
      requestAnimationFrame(animate);
    });
  }

  static animateProgressBar(element, targetWidth) {
    if (!element) return;
    
    element.style.transition = 'width 0.5s cubic-bezier(0.4, 0, 0.2, 1)';
    element.style.width = `${Math.max(0, Math.min(100, targetWidth))}%`;
  }

  static fadeIn(element, duration = 300) {
    if (!element) return Promise.resolve();
    
    return new Promise((resolve) => {
      element.style.opacity = '0';
      element.style.transform = 'translateY(10px)';
      element.style.transition = `all ${duration}ms ease`;
      
      requestAnimationFrame(() => {
        element.style.opacity = '1';
        element.style.transform = 'translateY(0)';
        
        setTimeout(() => {
          element.style.transition = '';
          resolve();
        }, duration);
      });
    });
  }
}

// ===== MAIN APPLICATION CLASS =====
class ByovdApp {
  constructor() {
    this.elementCache = new ElementCache();
    this.apiClient = new APIClient();
    this.driverHash = null;
    this.results = null;
    this.container = null;
    this.isInitialized = false;
    this.perfStart = performance.now();
    
    // Bind methods for performance
    this.handleCopyClick = this.handleCopyClick.bind(this);
    this.handleRefresh = this.handleRefresh.bind(this);
  }

  // ===== INITIALIZATION =====
  async init() {
    if (this.isInitialized) return;
    
    console.log('[BYOVD] Initializing application...');
    
    this.container = this.elementCache.get('#holygrailResults');
    if (!this.container) {
      console.error('[BYOVD] Container element not found');
      return;
    }

    this.driverHash = this.extractDriverHash();
    if (!this.driverHash) {
      this.showError('Invalid driver hash in URL');
      return;
    }

    this.setupEventListeners();
    this.showSkeleton();
    await this.loadData();
    
    this.isInitialized = true;
    
    const initTime = performance.now() - this.perfStart;
    console.log(`[BYOVD] Application initialized in ${initTime.toFixed(2)}ms`);
  }

  // ===== URL PARSING =====
  extractDriverHash() {
    // Try URL parameters first (most efficient)
    const urlParams = new URLSearchParams(window.location.search);
    const hashFromParam = urlParams.get('hash');
    if (hashFromParam) return hashFromParam;
    
    // Parse path efficiently
    const pathSegments = window.location.pathname.split('/').filter(Boolean);
    
    // Check for results pattern: /results/{hash}/byovd
    const resultsIndex = pathSegments.indexOf('results');
    if (resultsIndex !== -1 && pathSegments[resultsIndex + 1]) {
      return pathSegments[resultsIndex + 1];
    }
    
    // Check for byovd pattern: /byovd/{hash}
    const byovdIndex = pathSegments.indexOf('byovd');
    if (byovdIndex !== -1 && pathSegments[byovdIndex - 1]) {
      return pathSegments[byovdIndex - 1];
    }
    
    return null;
  }

  // ===== EVENT HANDLING =====
  setupEventListeners() {
    // Use event delegation for better performance
    this.container.addEventListener('click', (e) => {
      const copyButton = e.target.closest('[data-copy]');
      if (copyButton) {
        this.handleCopyClick(e, copyButton);
        return;
      }
      
      const refreshButton = e.target.closest('[data-refresh]');
      if (refreshButton) {
        this.handleRefresh(e);
        return;
      }
    });

    // Setup global event handlers
    window.runHolyGrailAnalysis = () => {
      if (this.driverHash) {
        window.location.href = `/holygrail?hash=${encodeURIComponent(this.driverHash)}`;
      }
    };

    window.generateDriverReport = () => {
      if (this.driverHash) {
        window.location.href = `/api/report/${encodeURIComponent(this.driverHash)}?download=true`;
      }
    };

    window.refreshByovdResults = () => this.handleRefresh();
  }

  async handleCopyClick(event, button) {
    event.preventDefault();
    
    const textToCopy = button.dataset.copy;
    if (!textToCopy) return;
    
    try {
      await navigator.clipboard.writeText(textToCopy);
      this.showCopyFeedback(button, 'Copied!', 'success');
    } catch (error) {
      // Fallback for older browsers
      this.fallbackCopy(textToCopy);
      this.showCopyFeedback(button, 'Copied!', 'success');
    }
  }

  fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
  }

  showCopyFeedback(button, message, type) {
    const originalText = button.textContent;
    const originalColor = button.style.backgroundColor;
    
    button.textContent = message;
    button.style.backgroundColor = type === 'success' ? '#10b981' : '#ef4444';
    button.style.transform = 'scale(0.95)';
    
    setTimeout(() => {
      button.textContent = originalText;
      button.style.backgroundColor = originalColor;
      button.style.transform = '';
    }, 1200);
  }

  handleRefresh() {
    this.showSkeleton();
    this.loadData(true); // Force refresh
  }

  // ===== DATA LOADING =====
  async loadData(forceRefresh = false) {
    try {
      // First check if data is available from template (SSR optimization)
      if (!forceRefresh && window.holygrailResults) {
        console.log('[BYOVD] Using server-side rendered data');
        await this.processData(window.holygrailResults);
        return;
      }

      console.log('[BYOVD] Fetching data from API...');
      const data = await this.apiClient.fetch(
        `/api/results/${encodeURIComponent(this.driverHash)}/holygrail`,
        { forceRefresh }
      );

      await this.processData(data);
      
    } catch (error) {
      console.error('[BYOVD] Failed to load data:', error);
      this.showError(`Failed to load results: ${error.message}`);
    }
  }

  async processData(rawData) {
    try {
      if (!rawData || typeof rawData !== 'object') {
        throw new Error('Invalid data format received');
      }

      const findings = rawData.findings || {};
      this.results = {
        status: (rawData.status || 'unknown').toLowerCase(),
        timestamp: rawData.timestamp || null,
        summary: findings.summary || {},
        detailed: findings.detailed_analysis || {}
      };

      const processTime = performance.now() - this.perfStart;
      console.log(`[BYOVD] Data processed in ${processTime.toFixed(2)}ms`);

      await this.renderResults();
      
    } catch (error) {
      console.error('[BYOVD] Data processing failed:', error);
      this.showError('Invalid data format received');
    }
  }

  // ===== RENDERING SYSTEM =====
  async renderResults() {
    const { summary, detailed, status, timestamp } = this.results;
    
    // Estimate complexity to choose rendering strategy
    const dataComplexity = JSON.stringify(detailed).length;
    
    if (dataComplexity > 10000) {
      // Use progressive rendering for large datasets
      await this.renderResultsProgressive();
    } else {
      // Quick render for smaller datasets
      const data = this.extractRenderData(summary, detailed, status, timestamp);
      const fragment = this.buildResultsFragment(data);
      
      // Use immediate update to bypass queue for critical operations
      DOMUtils.immediateUpdate([
        () => {
          this.container.innerHTML = '';
          this.container.appendChild(fragment);
        }
      ]);

      // Setup effects with proper batching
      await this.setupPostRenderEffects(data.score);
    }
    
    const renderTime = performance.now() - this.perfStart;
    console.log(`[BYOVD] Render completed in ${renderTime.toFixed(2)}ms`);
  }

  async renderResultsProgressive() {
    const { summary, detailed, status, timestamp } = this.results;
    const data = this.extractRenderData(summary, detailed, status, timestamp);
    
    // Clear container immediately
    this.container.innerHTML = '<div class="space-y-4" id="progressive-container"></div>';
    const progressiveContainer = this.container.querySelector('#progressive-container');
    
    // Render sections progressively
    const sections = [
      () => this.buildStatusSection(data),
      () => this.buildVerdictSection(data),
      () => this.buildBadgesSection(data),
      () => this.buildMetadataSection(data),
      () => this.buildCapabilitiesSection(data),
      () => this.buildImportsSection(data),
      () => this.buildBlocksSection(data),
      () => data.status !== 'completed' ? this.buildRunSection() : ''
    ].filter(Boolean);
    
    // Render each section in separate frames
    for (const sectionBuilder of sections) {
      await new Promise(resolve => {
        requestAnimationFrame(() => {
          const sectionHTML = sectionBuilder();
          if (sectionHTML) {
            const div = document.createElement('div');
            div.innerHTML = sectionHTML;
            progressiveContainer.appendChild(div.firstChild);
          }
          resolve();
        });
      });
    }
    
    // Setup effects after all sections are rendered
    await this.setupPostRenderEffects(data.score);
    
    const renderTime = performance.now() - this.perfStart;
    console.log(`[BYOVD] Progressive render completed in ${renderTime.toFixed(2)}ms`);
  }

  extractRenderData(summary, detailed, status, timestamp) {
    const driverName = summary.driver_name || detailed.name || 'Unknown driver';
    const isLol = this.getBool(summary.is_loldriver, detailed.is_loldriver);
    const isWin10Blocked = this.getBool(summary.is_win10_blocked, detailed.is_win10_blocked);
    const isWin11Blocked = this.getBool(summary.is_win11_blocked, detailed.is_win11_blocked);
    
    const imports = this.parseImports(detailed.critical_imports);
    const hasTerminate = this.getBool(detailed.has_terminate_process) || 
                        imports.some(s => /ZwTerminateProcess/i.test(s));
    const hasComms = this.getBool(detailed.has_communication) || 
                    imports.some(s => /(Zw|Nt)(DeviceIoControlFile|CreateFile|CreateSymbolicLink)/i.test(s));
    const avKiller = hasTerminate && (
      imports.some(s => /ZwOpenProcess/i.test(s)) || 
      imports.some(s => /PsLookupProcessByProcessId/i.test(s))
    );
    
    const hasDanger = !!(
      detailed.has_dangerous_imports ||
      (typeof detailed.critical_imports === 'string' && detailed.critical_imports.trim()) ||
      detailed.has_terminate_process || 
      detailed.has_communication
    );

    const isHolyGrail = hasDanger && !isLol && !isWin10Blocked && !isWin11Blocked;
    const score = this.calculateScore(isWin10Blocked, isWin11Blocked, isLol, hasDanger);

    return {
      driverName, isLol, isWin10Blocked, isWin11Blocked, imports,
      hasTerminate, hasComms, avKiller, hasDanger, isHolyGrail,
      score, status, timestamp, detailed
    };
  }

  buildResultsFragment(data) {
    // Build sections incrementally to avoid large string concatenations
    const sections = [];
    
    // Build critical sections first
    sections.push(this.buildStatusSection(data));
    sections.push(this.buildVerdictSection(data));
    sections.push(this.buildBadgesSection(data));
    
    // Create container with first batch
    const container = document.createElement('div');
    container.className = 'space-y-4';
    container.innerHTML = sections.join('');
    
    // Add remaining sections via DocumentFragment to avoid reflows
    const fragment = document.createDocumentFragment();
    const remainingSections = [
      this.buildMetadataSection(data),
      this.buildCapabilitiesSection(data), 
      this.buildImportsSection(data),
      this.buildBlocksSection(data),
      data.status !== 'completed' ? this.buildRunSection() : ''
    ].filter(Boolean);
    
    // Add remaining sections as separate elements to avoid large innerHTML operations
    remainingSections.forEach(sectionHTML => {
      const div = document.createElement('div');
      div.innerHTML = sectionHTML;
      while (div.firstChild) {
        fragment.appendChild(div.firstChild);
      }
    });
    
    container.appendChild(fragment);
    
    const outerFragment = document.createDocumentFragment();
    outerFragment.appendChild(container);
    
    return outerFragment;
  }

  async setupPostRenderEffects(score) {
    // Critical animations first (immediate)
    const scoreElement = this.elementCache.get('#scoreValue');
    const scoreBar = this.elementCache.get('#scoreBar');
    
    if (scoreElement) {
      AnimationSystem.animateNumber(scoreElement, 0, score);
    }
    
    // Non-critical updates can be batched
    DOMUtils.batchUpdate([
      () => {
        if (scoreBar) {
          setTimeout(() => {
            AnimationSystem.animateProgressBar(scoreBar, score);
          }, 200);
        }
      }
    ]);
  }

  // ===== SECTION BUILDERS =====
  buildStatusSection(data) {
    const statusMap = {
      completed: ['bg-green-600', 'COMPLETED'],
      error: ['bg-red-600', 'ERROR'], 
      pending: ['bg-yellow-600', 'PENDING'],
      unknown: ['bg-gray-600', 'UNKNOWN']
    };
    
    const [statusClass, statusText] = statusMap[data.status] || statusMap.unknown;
    const timestamp = data.timestamp ? new Date(data.timestamp).toLocaleString() : '—';

    return `
      <div class="cyber-card p-4">
        <div class="flex items-center justify-between flex-col sm:flex-row gap-3">
          <div class="flex items-center gap-3">
            <span class="px-2 py-1 text-sm rounded-lg ${statusClass} text-white">${statusText}</span>
            <h3 class="text-xl font-medium text-gray-100">${this.escapeHtml(data.driverName)}</h3>
          </div>
          <div class="text-base text-gray-400">Analyzed: ${this.escapeHtml(timestamp)}</div>
        </div>
      </div>
    `;
  }

  buildVerdictSection(data) {
    if (data.isHolyGrail) {
      return `
        <div class="verdict-holy">
          <div class="flex items-center gap-3 mb-3">
            <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-yellow-400 to-orange-500 flex items-center justify-center shadow-lg">
              <svg class="w-6 h-6 text-white" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/>
              </svg>
            </div>
            <div>
              <h3 class="text-2xl font-bold text-yellow-300">The Holy Grail Found</h3>
              <p class="text-yellow-200/80 text-base">Dangerous imports detected • Not on LOLDrivers • Not blocked</p>
            </div>
          </div>
        </div>
      `;
    }

    let title, description, severity;
    if (data.isLol) {
      title = 'Known Vulnerable Driver';
      description = 'Listed in LOLDrivers database';
      severity = 'warning';
    } else if (data.isWin10Blocked || data.isWin11Blocked) {
      title = 'Blocked Driver';
      description = 'Listed on Microsoft recommended driver block rules';
      severity = 'warning';
    } else if (data.hasDanger) {
      title = 'Potentially Interesting';
      description = 'Contains suspicious imports but may have limited exploitation potential';
      severity = 'info';
    } else {
      title = 'Low Risk Driver';
      description = 'No obvious signs of exploitation potential detected';
      severity = 'info';
    }

    const colors = severity === 'warning' ? 'border-yellow-500/30 bg-yellow-500/10' : 'border-blue-500/30 bg-blue-500/10';
    const statusDetails = [
      data.isLol ? 'LOLDrivers: LISTED' : 'LOLDrivers: NOT LISTED',
      data.isWin10Blocked ? 'Win10: BLOCKED' : 'Win10: ALLOWED',
      data.isWin11Blocked ? 'Win11: BLOCKED' : 'Win11: ALLOWED'
    ];

    return `
      <div class="verdict-neutral ${colors} border rounded-xl p-4">
        <h3 class="text-xl font-semibold text-white mb-1">${title}</h3>
        <p class="text-base text-gray-300 mb-2">${description}</p>
        <div class="text-sm text-gray-400">${statusDetails.join(' • ')}</div>
      </div>
    `;
  }

  buildBadgesSection(data) {
    const chipClass = (condition) => 
      `px-2 py-1 text-sm rounded-lg ${condition ? 'bg-red-600' : 'bg-green-600'} text-white`;

    let label, color;
    if (data.score >= 70) { label = 'HIGH'; color = 'text-green-300'; }
    else if (data.score >= 40) { label = 'MEDIUM'; color = 'text-yellow-300'; }
    else { label = 'LOW'; color = 'text-red-300'; }

    return `
      <div class="cyber-card p-4">
        <h3 class="text-xl font-medium text-gray-100 mb-3">Reputation & Policy</h3>
        <div class="mb-6 p-4 bg-black/20 rounded-lg">
          <div class="flex items-center justify-between mb-3">
            <span class="text-base text-gray-400 uppercase tracking-wide">BYOVD Score</span>
            <span class="${color} text-base font-medium">BYOVD Potential: ${label}</span>
          </div>
          <div class="flex items-center gap-4">
            <div class="score-value text-3xl font-bold ${color}" id="scoreValue">0</div>
            <div class="flex-1">
              <div class="progress-container">
                <div id="scoreBar" class="progress-bar" style="width: 0%"></div>
              </div>
            </div>
          </div>
        </div>
        <div class="flex flex-wrap gap-2">
          <span class="${chipClass(data.isLol)}">
            ${data.isLol ? 'LoLDrivers: LISTED' : 'LoLDrivers: Not listed'}
          </span>
          <span class="${chipClass(data.isWin10Blocked)}">
            ${data.isWin10Blocked ? 'Windows 10: BLOCKED' : 'Windows 10: Not blocked'}
          </span>
          <span class="${chipClass(data.isWin11Blocked)}">
            ${data.isWin11Blocked ? 'Windows 11: BLOCKED' : 'Windows 11: Not blocked'}
          </span>
        </div>
      </div>
    `;
  }

  buildMetadataSection(data) {
    const detailed = data.detailed;
    const sha = detailed.sha256 || 'Unknown';
    
    // Pre-escape values to avoid doing it during render
    const escapedData = {
      fileVersion: this.escapeHtml(detailed.file_version || 'Unknown'),
      architecture: this.escapeHtml(detailed.architecture || 'Unknown'),
      size: this.escapeHtml(detailed.size || 'Unknown'),
      originalFilename: this.escapeHtml(detailed.original_filename || 'Unknown'),
      path: this.escapeHtml(detailed.path || 'Unknown'),
      sha: this.escapeHtml(sha),
      compileTime: this.escapeHtml(detailed.compile_time || 'Unknown')
    };
    
    const copyButton = sha !== 'Unknown' 
      ? `<button class="ml-2 text-sm px-2 py-0.5 border border-gray-700 rounded hover:bg-gray-800 transition-colors" data-copy="${sha}">copy</button>`
      : '';

    return `
      <div class="cyber-card p-4">
        <h3 class="text-xl font-medium text-gray-100 mb-3">Metadata</h3>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <span class="text-base text-gray-500">File Version:</span>
            <p class="text-gray-200 font-mono text-base break-all">${escapedData.fileVersion}</p>
          </div>
          <div>
            <span class="text-base text-gray-500">Architecture:</span>
            <p class="text-gray-200 font-mono text-base break-all">${escapedData.architecture}</p>
          </div>
          <div>
            <span class="text-base text-gray-500">File Size:</span>
            <p class="text-gray-200">${escapedData.size}</p>
          </div>
          <div>
            <span class="text-base text-gray-500">Compile Time:</span>
            <p class="text-gray-200 font-mono text-base break-all">${escapedData.compileTime}</p>
          </div>
          <div class="sm:col-span-2">
            <span class="text-base text-gray-500">Original Filename:</span>
            <p class="text-gray-200 font-mono text-base break-all">${escapedData.originalFilename}</p>
          </div>
          <div class="sm:col-span-2">
            <span class="text-base text-gray-500">SHA-256:</span>
            <div class="mt-1 flex items-center">
              <code class="text-gray-200 font-mono text-base break-all bg-black/30 p-3 rounded-lg flex-1">${escapedData.sha}</code>
              ${copyButton}
            </div>
          </div>
          <div class="sm:col-span-2">
            <span class="text-base text-gray-500">Path:</span>
            <p class="text-gray-200 font-mono text-base break-all">${escapedData.path}</p>
          </div>
        </div>
      </div>
    `;
  }

  buildCapabilitiesSection(data) {
    const chips = [];

    if (data.avKiller) {
      chips.push(`
        <span class="inline-flex items-center gap-2 px-2.5 py-1 rounded-md text-sm border border-yellow-500/30 bg-yellow-500/10 text-yellow-200">
          <span class="w-1.5 h-1.5 rounded-full bg-yellow-400"></span>
          <span class="font-medium">AV-killer primitive</span>
        </span>
      `);
    } else if (data.hasTerminate) {
      chips.push(`
        <span class="inline-flex items-center gap-2 px-2.5 py-1 rounded-md text-sm border border-purple-500/30 bg-purple-500/10 text-purple-200">
          <span class="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
          <span class="font-medium">Terminate arbitrary process</span>
        </span>
      `);
    }

    if (data.hasComms) {
      chips.push(`
        <span class="inline-flex items-center gap-2 px-2.5 py-1 rounded-md text-sm border border-cyan-500/30 bg-cyan-500/10 text-cyan-200">
          <span class="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
          <span class="font-medium">User-mode IOCTL comms</span>
        </span>
      `);
    }

    const content = chips.length 
      ? `<div class="flex flex-wrap gap-2">${chips.join('')}</div>`
      : '<p class="text-base text-gray-500">No offensive primitives observed.</p>';

    return `
      <div class="cyber-card p-4">
        <h3 class="text-xl font-medium text-gray-100 mb-3">User Mode Capabilities</h3>
        ${content}
      </div>
    `;
  }

  buildImportsSection(data) {
    const chips = data.imports.length
      ? data.imports.map(imp => 
          `<span class="px-2 py-1 rounded-md border border-gray-700 text-sm text-gray-200 bg-black/40 font-mono">${this.escapeHtml(imp)}</span>`
        ).join(' ')
      : '<span class="text-base text-gray-500">No critical imports reported.</span>';

    return `
      <div class="cyber-card p-4">
        <h3 class="text-xl font-medium text-gray-100 mb-3">Critical Imports</h3>
        <div class="flex flex-wrap gap-2 mb-4">${chips}</div>
        <p class="text-sm text-gray-500">Heuristics identify privileged primitives commonly exploited in BYOVD attacks.</p>
      </div>
    `;
  }

  buildBlocksSection(data) {
    const buildCard = (name, blocked, reason, details) => {
      const detailsHtml = blocked && details ? `
        <details class="mt-2">
          <summary class="cursor-pointer text-red-300 hover:text-red-200 text-base">Show rule details</summary>
          <div class="mt-2 text-sm text-gray-300 space-y-1">
            ${details.matched_rule?.id ? `<div><strong>Rule ID:</strong> ${this.escapeHtml(details.matched_rule.id)}</div>` : ''}
            ${details.matched_rule?.friendly_name ? `<div><strong>Rule:</strong> ${this.escapeHtml(details.matched_rule.friendly_name)}</div>` : ''}
            ${details.matched_rule?.file_name ? `<div><strong>File:</strong> ${this.escapeHtml(details.matched_rule.file_name)}</div>` : ''}
            ${details.matched_rule?.maximum_file_version ? `<div><strong>Max Version:</strong> ${this.escapeHtml(details.matched_rule.maximum_file_version)}</div>` : ''}
            ${details.detailed_explanation ? `<pre class="whitespace-pre-wrap bg-black/20 p-2 rounded mt-2">${this.escapeHtml(details.detailed_explanation)}</pre>` : ''}
          </div>
        </details>
      ` : '';

      return `
        <div class="border ${blocked ? 'border-red-500/30' : 'border-green-500/30'} rounded-lg p-3 bg-black/30">
          <div class="flex items-center justify-between mb-1">
            <h4 class="font-medium text-gray-100 text-lg">${this.escapeHtml(name)}</h4>
            <span class="px-2 py-0.5 text-sm rounded ${blocked ? 'bg-red-600' : 'bg-green-600'} text-white">
              ${blocked ? 'BLOCKED' : 'ALLOWED'}
            </span>
          </div>
          <p class="text-sm text-gray-400">${this.escapeHtml(reason || 'Status unknown')}</p>
          ${detailsHtml}
        </div>
      `;
    };

    return `
      <div class="cyber-card p-4">
        <h3 class="text-xl font-medium text-gray-100 mb-3">Windows Block Status</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          ${buildCard('Windows 10', data.isWin10Blocked, data.detailed.win10_block_reason, data.detailed.win10_blocking_details)}
          ${buildCard('Windows 11', data.isWin11Blocked, data.detailed.win11_block_reason, data.detailed.win11_blocking_details)}
        </div>
      </div>
    `;
  }

  buildRunSection() {
    return `
      <div class="text-center py-6">
        <p class="text-gray-400 text-base">Need to (re)run HolyGrail on this driver?</p>
        <a href="/holygrail?hash=${encodeURIComponent(this.driverHash)}"
           class="inline-block mt-3 px-4 py-2 bg-purple-500 text-white rounded-lg hover:bg-purple-600 transition-colors text-base">
          Run HolyGrail Analysis
        </a>
      </div>
    `;
  }

  // ===== UI HELPERS =====
  showSkeleton() {
    DOMUtils.setHTML(this.container, `
      <div class="space-y-4">
        <div class="cyber-card p-4"><div class="skeleton animate h-16"></div></div>
        <div class="cyber-card p-4"><div class="skeleton animate h-24"></div></div>
        <div class="cyber-card p-4"><div class="skeleton animate h-32"></div></div>
      </div>
    `);
  }

  showError(message) {
    DOMUtils.setHTML(this.container, `
      <div class="text-center py-8">
        <div class="text-red-500 mb-4">
          <svg class="w-16 h-16 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                  d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
        </div>
        <h3 class="text-xl font-medium text-gray-300 mb-2">Error Loading Results</h3>
        <p class="text-gray-500 text-base">${this.escapeHtml(message)}</p>
      </div>
    `);
  }

  // ===== UTILITY METHODS =====
  calculateScore(win10, win11, isLol, hasDanger) {
    if (win11 && win10) return 0;
    let score = 0;
    if (hasDanger) score += 55;
    if (!win11) score += 25; else score -= 50;
    if (!win10) score += 20; else score -= 20;
    if (!isLol) score += 10; else score -= 5;
    return Math.max(0, Math.min(100, score));
  }

  escapeHtml(text) {
    const str = (text || '').toString();
    
    // Quick check if escaping is needed
    if (!/[&<>"']/.test(str)) {
      return str;
    }
    
    // Efficient string replacement
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  getBool(...values) {
    for (const val of values) {
      if (typeof val === 'boolean') return val;
    }
    return false;
  }

  parseImports(csv) {
    if (!csv || typeof csv !== 'string') return [];
    return csv.split(',').map(s => s.trim()).filter(Boolean);
  }

  // ===== CLEANUP =====
  destroy() {
    if (this.elementCache) {
      this.elementCache.destroy();
    }
    if (this.apiClient) {
      this.apiClient.destroy();
    }
    this.isInitialized = false;
  }
}

// ===== APPLICATION BOOTSTRAP =====
let app = null;

function initializeApp() {
  if (app) {
    app.destroy();
  }
  
  app = new ByovdApp();
  app.init().catch(error => {
    console.error('[BYOVD] Failed to initialize:', error);
  });
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeApp);
} else {
  initializeApp();
}

// Handle page visibility changes for performance
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden' && app) {
    // Clean up resources when page is hidden
    app.apiClient.clearCache();
  }
});

// Global error handler
window.addEventListener('unhandledrejection', (event) => {
  console.error('[BYOVD] Unhandled promise rejection:', event.reason);
});

// Expose app instance for debugging
if (typeof window !== 'undefined') {
  window.__byovdApp = app;
}