// app/static/js/byovd/core.js
// /results/<hash>/byovd page entry: fetches BYOVD analysis, renders verdict,
// details, imports, YARA matches, and Win10/11 mitigation status.

import { PERF_CONFIG, ElementCache, DOMUtils, AnimationSystem } from './utils.js';
import { APIClient } from './api.js';
import { escapeHtml as _escapeHtml } from '../utils/escape.js';

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
    const sevMap = {
      completed: 'clean',
      error:     'critical',
      pending:   'medium',
      unknown:   'muted',
    };
    const sev = sevMap[data.status] || 'muted';
    const statusText = (data.status || 'UNKNOWN').toUpperCase();
    const timestamp = data.timestamp ? new Date(data.timestamp).toLocaleString() : '—';

    return `
      <div class="lb-panel">
        <div class="lb-panel-hdr">
          <span class="lb-glyph">▸</span>${this.escapeHtml(data.driverName)}
          <span style="margin-left: auto; display: flex; gap: 8px; align-items: center;">
            <span class="lb-tag ${sev}">${statusText}</span>
            <span class="lb-muted lb-mono" style="font-size: 12px;">${this.escapeHtml(timestamp)}</span>
          </span>
        </div>
      </div>
    `;
  }

  buildVerdictSection(data) {
    if (data.isHolyGrail) {
      return `
        <div style="border: 1px solid var(--lb-sev-medium); padding: 12px 14px; display: flex; align-items: center; gap: 12px; background: rgba(250, 204, 21, 0.04);">
          <span class="lb-tag medium">⚑ HolyGrail</span>
          <div style="flex: 1;">
            <div class="lb-strong" style="font-size: 14px;">The Holy Grail Found</div>
            <div class="lb-muted" style="font-size: 12px;">Critical imports observed · Not on LOLDrivers · Not blocked</div>
          </div>
        </div>
      `;
    }

    let title, description, severity;
    if (data.isLol) {
      title = 'Known Vulnerable Driver';
      description = 'Listed in LOLDrivers database';
      severity = 'medium';
    } else if (data.isWin10Blocked || data.isWin11Blocked) {
      title = 'Blocked Driver';
      description = 'Listed on Microsoft recommended driver block rules';
      severity = 'medium';
    } else if (data.hasDanger) {
      title = 'Potentially Interesting';
      description = 'Contains critical imports but may have limited exploitation potential';
      severity = 'info';
    } else {
      title = 'Low BYOVD Potential';
      description = 'No obvious signs of exploitation potential observed';
      severity = 'info';
    }

    const borderColor = severity === 'medium' ? 'var(--lb-sev-medium)' : 'var(--lb-border-hi)';
    const statusDetails = [
      data.isLol           ? 'LOLDrivers: LISTED'  : 'LOLDrivers: NOT LISTED',
      data.isWin10Blocked  ? 'Win10: BLOCKED'      : 'Win10: ALLOWED',
      data.isWin11Blocked  ? 'Win11: BLOCKED'      : 'Win11: ALLOWED',
    ];

    return `
      <div style="border: 1px solid ${borderColor}; padding: 12px 14px;">
        <div class="lb-strong" style="font-size: 14px; margin-bottom: 4px;">${title}</div>
        <div class="lb-dim" style="font-size: 12px; margin-bottom: 6px;">${description}</div>
        <div class="lb-muted lb-mono" style="font-size: 11px;">${statusDetails.join(' · ')}</div>
      </div>
    `;
  }

  buildBadgesSection(data) {
    let label, scoreColor;
    if      (data.score >= 70) { label = 'HIGH';   scoreColor = 'var(--lb-sev-low)'; }
    else if (data.score >= 40) { label = 'MEDIUM'; scoreColor = 'var(--lb-sev-medium)'; }
    else                       { label = 'LOW';    scoreColor = 'var(--lb-text-mute)'; }

    const chip = (condition, hitText, okText) =>
      `<span class="lb-tag ${condition ? 'critical' : 'clean'}">${condition ? hitText : okText}</span>`;

    return `
      <div class="lb-panel">
        <div class="lb-panel-hdr"><span class="lb-glyph">▸</span>Reputation &amp; Policy</div>
        <div class="lb-panel-body">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px;">
            <span class="lb-eyebrow">BYOVD Score</span>
            <span style="font-size: 12px; color: ${scoreColor};">Potential: ${label}</span>
          </div>
          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
            <div id="scoreValue" class="lb-mono lb-strong" style="font-size: 28px; line-height: 1; color: ${scoreColor};">0</div>
            <div style="flex: 1; height: 4px; background: var(--lb-bg); border: 1px solid var(--lb-border); position: relative; overflow: hidden;">
              <div id="scoreBar" style="position: absolute; top: 0; left: 0; height: 100%; width: 0%; background: ${scoreColor}; transition: width var(--lb-transition);"></div>
            </div>
          </div>
          <div style="display: flex; flex-wrap: wrap; gap: 6px;">
            ${chip(data.isLol,           'LOLDrivers: Listed',     'LOLDrivers: Not Listed')}
            ${chip(data.isWin10Blocked,  'Windows 10: Blocked',    'Windows 10: Allowed')}
            ${chip(data.isWin11Blocked,  'Windows 11: Blocked',    'Windows 11: Allowed')}
          </div>
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
      ? `<button class="lb-btn lb-btn-ghost" style="padding: 2px 8px; font-size: 11px;" data-copy="${sha}">Copy</button>`
      : '';

    const field = (label, value, mono = true, span = false) => `
      <div${span ? ' style="grid-column: span 2;"' : ''}>
        <div class="lb-eyebrow" style="margin-bottom: 2px;">${label}</div>
        <div class="lb-strong${mono ? ' lb-mono' : ''}" style="font-size: 13px; word-break: break-all;">${value}</div>
      </div>
    `;

    return `
      <div class="lb-panel">
        <div class="lb-panel-hdr"><span class="lb-glyph">▸</span>Metadata</div>
        <div class="lb-panel-body">
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
            ${field('File Version',      escapedData.fileVersion)}
            ${field('Architecture',      escapedData.architecture)}
            ${field('File Size',         escapedData.size, false)}
            ${field('Compile Time',      escapedData.compileTime)}
            ${field('Original Filename', escapedData.originalFilename, true, true)}
            <div style="grid-column: span 2;">
              <div class="lb-eyebrow" style="margin-bottom: 2px;">SHA-256</div>
              <div style="display: flex; align-items: center; gap: 8px;">
                <code class="lb-mono lb-strong" style="flex: 1; padding: 6px 8px; background: var(--lb-bg); border: 1px solid var(--lb-border); font-size: 12px; word-break: break-all;">${escapedData.sha}</code>
                ${copyButton}
              </div>
            </div>
            ${field('Path', escapedData.path, true, true)}
          </div>
        </div>
      </div>
    `;
  }

  buildCapabilitiesSection(data) {
    const chips = [];

    if (data.avKiller) {
      chips.push('<span class="lb-tag critical">AV-Killer Primitive</span>');
    } else if (data.hasTerminate) {
      chips.push('<span class="lb-tag medium">Terminate Arbitrary Process</span>');
    }
    if (data.hasComms) {
      chips.push('<span class="lb-tag info">User-Mode IOCTL Comms</span>');
    }

    const content = chips.length
      ? `<div style="display: flex; flex-wrap: wrap; gap: 6px;">${chips.join('')}</div>`
      : '<div class="lb-muted" style="font-size: 12px;">No offensive primitives observed.</div>';

    return `
      <div class="lb-panel">
        <div class="lb-panel-hdr"><span class="lb-glyph">▸</span>User Mode Capabilities</div>
        <div class="lb-panel-body">${content}</div>
      </div>
    `;
  }

  buildImportsSection(data) {
    const chips = data.imports.length
      ? data.imports.map(imp =>
          `<span class="lb-tag muted lb-mono">${this.escapeHtml(imp)}</span>`
        ).join(' ')
      : '<span class="lb-muted" style="font-size: 12px;">No critical imports reported.</span>';

    return `
      <div class="lb-panel">
        <div class="lb-panel-hdr">
          <span class="lb-glyph">▸</span>Critical Imports
          <span class="lb-panel-badge">${data.imports.length}</span>
        </div>
        <div class="lb-panel-body">
          <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px;">${chips}</div>
          <div class="lb-muted" style="font-size: 11px;">Heuristics identify privileged primitives commonly exploited in BYOVD attacks.</div>
        </div>
      </div>
    `;
  }

  buildBlocksSection(data) {
    const buildBlock = (name, blocked, reason, details) => {
      const detailsHtml = blocked && details ? `
        <details style="margin-top: 8px;">
          <summary class="lb-accent" style="cursor: pointer; font-size: 12px;">Show rule details</summary>
          <div style="margin-top: 6px; display: flex; flex-direction: column; gap: 4px; font-size: 12px;">
            ${details.matched_rule?.id ? `<div><span class="lb-eyebrow">Rule ID</span> <span class="lb-mono lb-strong">${this.escapeHtml(details.matched_rule.id)}</span></div>` : ''}
            ${details.matched_rule?.friendly_name ? `<div><span class="lb-eyebrow">Rule</span> <span class="lb-strong">${this.escapeHtml(details.matched_rule.friendly_name)}</span></div>` : ''}
            ${details.matched_rule?.file_name ? `<div><span class="lb-eyebrow">File</span> <span class="lb-mono lb-strong">${this.escapeHtml(details.matched_rule.file_name)}</span></div>` : ''}
            ${details.matched_rule?.maximum_file_version ? `<div><span class="lb-eyebrow">Max Version</span> <span class="lb-mono lb-strong">${this.escapeHtml(details.matched_rule.maximum_file_version)}</span></div>` : ''}
            ${details.detailed_explanation ? `<pre class="lb-mono lb-dim" style="margin-top: 6px; padding: 8px; background: var(--lb-bg); border-left: 1px solid var(--lb-border-hi); font-size: 12px; white-space: pre-wrap; word-break: break-all;">${this.escapeHtml(details.detailed_explanation)}</pre>` : ''}
          </div>
        </details>
      ` : '';

      return `
        <div style="border: 1px solid ${blocked ? 'rgba(248, 113, 113, 0.22)' : 'rgba(74, 222, 128, 0.22)'}; padding: 12px;">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
            <span class="lb-strong" style="font-size: 14px;">${this.escapeHtml(name)}</span>
            <span class="lb-tag ${blocked ? 'critical' : 'clean'}">${blocked ? 'Blocked' : 'Allowed'}</span>
          </div>
          <div class="lb-muted" style="font-size: 12px;">${this.escapeHtml(reason || 'Status unknown')}</div>
          ${detailsHtml}
        </div>
      `;
    };

    return `
      <div class="lb-panel">
        <div class="lb-panel-hdr"><span class="lb-glyph">▸</span>Windows Block Status</div>
        <div class="lb-panel-body">
          <div class="lb-grid-2">
            ${buildBlock('Windows 10', data.isWin10Blocked, data.detailed.win10_block_reason, data.detailed.win10_blocking_details)}
            ${buildBlock('Windows 11', data.isWin11Blocked, data.detailed.win11_block_reason, data.detailed.win11_blocking_details)}
          </div>
        </div>
      </div>
    `;
  }

  buildRunSection() {
    return `
      <div style="text-align: center; padding: 16px;">
        <div class="lb-muted" style="font-size: 12px; margin-bottom: 10px;">Need to (re)run HolyGrail on this driver?</div>
        <a href="/holygrail?hash=${encodeURIComponent(this.driverHash)}" class="lb-btn lb-btn-primary">
          Run HolyGrail Analysis
        </a>
      </div>
    `;
  }

  // ===== UI HELPERS =====
  showSkeleton() {
    DOMUtils.setHTML(this.container, `
      <div style="display: flex; flex-direction: column; gap: 12px;">
        <div class="lb-panel"><div class="lb-panel-body" style="height: 60px; background: linear-gradient(90deg, var(--lb-bg-soft), var(--lb-panel-hi), var(--lb-bg-soft)); animation: lb-pulse 1.6s ease-in-out infinite;"></div></div>
        <div class="lb-panel"><div class="lb-panel-body" style="height: 90px; background: linear-gradient(90deg, var(--lb-bg-soft), var(--lb-panel-hi), var(--lb-bg-soft)); animation: lb-pulse 1.6s ease-in-out infinite;"></div></div>
        <div class="lb-panel"><div class="lb-panel-body" style="height: 120px; background: linear-gradient(90deg, var(--lb-bg-soft), var(--lb-panel-hi), var(--lb-bg-soft)); animation: lb-pulse 1.6s ease-in-out infinite;"></div></div>
      </div>
    `);
  }

  showError(message) {
    DOMUtils.setHTML(this.container, `
      <div class="lb-empty threats" style="flex-direction: column; padding: 32px 16px;">
        <svg width="32" height="32" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="margin-bottom: 10px;">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        <div class="lb-strong" style="margin-bottom: 4px;">Error Loading Results</div>
        <div class="lb-muted" style="font-size: 12px;">${this.escapeHtml(message)}</div>
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

  // Delegates to the shared utility so all `this.escapeHtml(x)` call sites stay unchanged.
  escapeHtml(text) { return _escapeHtml(text); }

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