// app/static/js/holygrail/core.js
// DOMContentLoaded entry for the /holygrail page.
// Drag-drop upload, BYOVD analysis flow, verdict + score rendering.

import { HOLYGRAIL, ElementCache, AnimationUtils, DOMUtils } from './utils.js';
import { escapeHtml } from '../utils/escape.js';


document.addEventListener('DOMContentLoaded', () => {
  // Pre-cache all critical elements for better performance
  const criticalElements = [
    'dz', 'fileInput', 'fileInputSmall', 'uploadCard', 'consoleCard', 'resultsCard',
    'stepper', 'consoleTitle', 'progressBar', 'consoleLog', 'cancelBtn',
    's1', 's2', 's3', 'summaryName', 'summaryType', 'summarySize', 'summaryTime',
    'summaryMd5', 'summarySha', 'scoreBar', 'scoreValue', 'scoreLabel',
    'lolBadge', 'w10Badge', 'w11Badge', 'resetBtn', 'verdictBanner',
    'sha256Full', 'copyShaBtn', 'fileVersion', 'fileSizePretty', 'arch',
    'originalFilename', 'compileTime', 'importsCard', 'importsWrap',
    'blockRows', 'toastContainer'
  ];
  
  ElementCache.preCache(criticalElements);

  let currentHash = null;
  let currentName = null;
  let abort = false;
  let analysisComplete = false;

  // FIXED: Proper drag and drop implementation
  let dragCounter = 0;
  const dropZone = ElementCache.get('dz');
  
  if (dropZone) {
    // Prevent default drag behaviors on the entire document
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      document.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
      }, false);
    });

    // Handle dragenter
    dropZone.addEventListener('dragenter', (e) => {
      e.preventDefault();
      e.stopPropagation();
      dragCounter++;
      if (dragCounter === 1) {
        DOMUtils.toggleClass(dropZone, 'drag-over', true);
      }
    }, false);

    // Handle dragover
    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      e.stopPropagation();
      e.dataTransfer.dropEffect = 'copy'; // Show copy cursor
    }, false);

    // Handle dragleave
    dropZone.addEventListener('dragleave', (e) => {
      e.preventDefault();
      e.stopPropagation();
      dragCounter--;
      if (dragCounter === 0) {
        DOMUtils.toggleClass(dropZone, 'drag-over', false);
      }
    }, false);

    // Handle drop - MOST IMPORTANT
    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      e.stopPropagation();
      
      dragCounter = 0;
      DOMUtils.toggleClass(dropZone, 'drag-over', false);
      
      // Get the files from the drop event
      const files = e.dataTransfer.files;
      if (files && files.length > 0) {
        handleFiles(files);
      }
    }, false);
  }

  // Optimized keyboard accessibility
  ElementCache.get('dz')?.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { 
      e.preventDefault(); 
      ElementCache.get('fileInput')?.click(); 
    }
  });

  // File input handlers with debouncing for better performance
  let fileInputTimeout;
  const handleFileInput = (e) => {
    clearTimeout(fileInputTimeout);
    fileInputTimeout = setTimeout(() => handleFiles(e.target.files), 50);
  };

  ElementCache.get('fileInput')?.addEventListener('change', handleFileInput);
  ElementCache.get('fileInputSmall')?.addEventListener('change', handleFileInput);

  // Button handlers
  ElementCache.get('cancelBtn')?.addEventListener('click', () => {
    abort = true;
    toast('Analysis cancelled by user', 'warning');
    hardReset();
  });
  
  ElementCache.get('resetBtn')?.addEventListener('click', hardReset);
  
  ElementCache.get('copyShaBtn')?.addEventListener('click', async () => {
    const text = ElementCache.get('sha256Full')?.textContent?.trim();
    if (text && text !== 'Unknown') {
      try {
        await navigator.clipboard.writeText(text);
        toast('SHA256 hash copied to clipboard', 'success');
      } catch (err) {
        toast('Failed to copy hash to clipboard', 'error');
      }
    } else {
      toast('No hash available to copy', 'warning');
    }
  });
  localStorage.setItem('currentFileExtension', 'sys');

  // ADD THE FUNCTION HERE
  function runStaticScan() {
    if (!currentHash) {
      console.error('No file hash available');
      toast('No file hash available for static analysis', 'error');
      return;
    }
    
    // Navigate to static analysis
    window.location.href = `/analyze/static/${currentHash}`;
  }

  // Make it globally accessible
  window.runStaticScan = runStaticScan;

  // ====== Optimized File Handling ======
  function handleFiles(fileList) {
    const file = fileList && fileList[0];
    if (!file) return;
    
    if (!isAllowed(file.name)) {
      toast('Unsupported file type. Please use .sys or .dll files', 'error');
      return;
    }
    
    if (file.size > HOLYGRAIL.maxFileSize) {
      const maxSizeMB = (HOLYGRAIL.maxFileSize / 1024 / 1024).toFixed(1);
      const fileSizeMB = (file.size / 1024 / 1024).toFixed(1);
      toast(`File too large (${fileSizeMB}MB). Maximum size is ${maxSizeMB}MB`, 'error');
      return;
    }

    abort = false;
    analysisComplete = false;
    showStepper();
    stageUpload(file);
    upload(file);
  }

  function stageUpload(file) {
    currentName = file.name;
    
    // Batch DOM updates for better performance
    const updates = [
      { element: ElementCache.get('summaryName'), operations: [(el) => DOMUtils.setText(el, file.name)] },
      { element: ElementCache.get('summaryType'), operations: [(el) => DOMUtils.setText(el, extName(file.name).toUpperCase())] },
      { element: ElementCache.get('summarySize'), operations: [(el) => DOMUtils.setText(el, prettySize(file.size))] },
      { element: ElementCache.get('summaryTime'), operations: [(el) => DOMUtils.setText(el, prettyTime(Date.now()))] },
      { element: ElementCache.get('consoleTitle'), operations: [(el) => DOMUtils.setText(el, file.name)] }
    ];
    
    DOMUtils.batchUpdate(updates);

    // Enhanced stepper progression
    markStep(ElementCache.get('s1'), 'done');
    markStep(ElementCache.get('s2'), 'active');

    // Enhanced UI transitions with GPU acceleration
    fadeOut(ElementCache.get('uploadCard'), () => {
      fadeIn(ElementCache.get('consoleCard'));
    });
    
    clearConsole();
    progress(0);
    log('Uploading driver…');
  }



  // ====== Optimized Network Operations ======
  function upload(file) {
    const form = new FormData();
    form.append('file', file);
    
    fetch('/holygrail', { 
      method: 'POST', 
      body: form
    })
      .then(jsonOrThrow)
      .then(data => {
        if (data.error) throw new Error(data.error);
        
        const info = data.file_info;
        if (!info) throw new Error('No file_info in response');

        // Store file information from backend and batch updates
        currentHash = info.md5;
        
        const updates = [
          { element: ElementCache.get('summaryMd5'), operations: [(el) => DOMUtils.setText(el, info.md5 || '—')] },
          { element: ElementCache.get('summarySha'), operations: [(el) => DOMUtils.setText(el, info.sha256 || '—')] },
          { element: ElementCache.get('fileVersion'), operations: [(el) => DOMUtils.setText(el, info.file_version || 'Unknown')] },
          { element: ElementCache.get('fileSizePretty'), operations: [(el) => DOMUtils.setText(el, prettySize(info.size))] },
          { element: ElementCache.get('arch'), operations: [(el) => DOMUtils.setText(el, info.architecture || extName(info.extension) || 'Unknown')] }
        ];
        
        DOMUtils.batchUpdate(updates);

        log('Driver uploaded.');
        progress(20);
        
        runAnalysis(currentHash);
      })
      .catch(err => {
        console.error('Upload error:', err);
        toast(`Upload failed: ${err.message}`, 'error');
        hardReset();
      });
  }

  function runAnalysis(md5) {
    if (!md5) {
      toast('Missing MD5 hash for analysis', 'error');
      return;
    }
    
    if (abort) return;

    const steps = [
      'Parsing PE headers…',
      'Extracting imports…',
      'Cross-referencing LOLDrivers…',
      'Checking Windows block list…',
      'Evaluating BYOVD heuristics…'
    ];

    let stepIndex = 0;
    const stepInterval = setInterval(() => {
      if (abort) {
        clearInterval(stepInterval);
        return;
      }
      
      if (stepIndex < steps.length) {
        log(steps[stepIndex]);
        progress(20 + Math.round((stepIndex + 1) * 10));
        stepIndex++;
      } else {
        clearInterval(stepInterval);
      }
    }, HOLYGRAIL.stepDurationMs);

    fetch(`/holygrail?hash=${encodeURIComponent(md5)}`, { method: 'GET' })
      .then(jsonOrThrow)
      .then(raw => {
        if (abort) return;
        if (raw.error) throw new Error(raw.error);

        clearInterval(stepInterval);

        progress(80);
        const normalized = normalize(raw.results || raw);

        // Carry compile_time into detailed for rendering
        if (!normalized.detailed) normalized.detailed = {};
        if (!normalized.detailed.compile_time && raw.compile_time) {
          normalized.detailed.compile_time = raw.compile_time;
        }

        log('Scan complete.');
        progress(100);

        setTimeout(() => showResults(normalized), 250);
      })
      .catch(err => {
        clearInterval(stepInterval);
        console.error('Analysis error:', err);
        toast(`Analysis failed: ${err.message}`, 'error');
        hardReset();
      });
  }

  // ====== Optimized Results Display ======
  function showResults(normalized) {
    if (abort) return;

    markStep(ElementCache.get('s2'), 'done');
    markStep(ElementCache.get('s3'), 'active');

    fadeOut(ElementCache.get('consoleCard'), () => {
      fadeIn(ElementCache.get('resultsCard'));
      renderResults(normalized);
      markStep(ElementCache.get('s3'), 'done');
      
      analysisComplete = true;
      setTimeout(() => {
        hideStepper();
      }, 1000);
    });
  }

  function renderResults(norm) {
    const { summary: s, detailed: d } = norm;
    
    // Get data from backend - NO frontend logic decisions
    const win10 = !!s.is_win10_blocked;
    const win11 = !!s.is_win11_blocked;
    const isLol = !!s.is_loldriver;
    
    const hasDanger = !!(
      d.has_dangerous_imports ||
      (typeof d.critical_imports === 'string' && d.critical_imports.trim()) ||
      d.has_terminate_process || 
      d.has_communication
    );

    // Render verdict banner based on backend data
    const isHolyGrail = hasDanger && !isLol && !win10 && !win11;
    DOMUtils.setHTML(ElementCache.get('verdictBanner'), isHolyGrail ? 
      renderHolyGrailBanner() : 
      renderNeutralBanner(isLol, win10, win11, hasDanger));

    // Update status badges with backend data
    updateBadge(ElementCache.get('lolBadge'), isLol ? 'Known LOLDriver' : 'Not Listed', isLol ? 'danger' : 'success');
    updateBadge(ElementCache.get('w10Badge'), win10 ? 'Blocked' : 'Allowed', win10 ? 'danger' : 'success');
    updateBadge(ElementCache.get('w11Badge'), win11 ? 'Blocked' : 'Allowed', win11 ? 'danger' : 'success');

    // Batch file information updates
    const fileUpdates = [
      { element: ElementCache.get('sha256Full'), operations: [(el) => DOMUtils.setText(el, d.sha256 || 'Unknown')] },
      { element: ElementCache.get('fileVersion'), operations: [(el) => DOMUtils.setText(el, d.file_version || ElementCache.get('fileVersion').textContent || 'Unknown')] },
      { element: ElementCache.get('arch'), operations: [(el) => DOMUtils.setText(el, d.architecture || ElementCache.get('arch').textContent || 'Unknown')] }
    ];
    
    if (d.size) {
      fileUpdates.push({ element: ElementCache.get('fileSizePretty'), operations: [(el) => DOMUtils.setText(el, d.size)] });
    }
    
    if (ElementCache.get('originalFilename')) {
      fileUpdates.push({ element: ElementCache.get('originalFilename'), operations: [(el) => DOMUtils.setText(el, d.original_filename || 'Unknown')] });
    }
    
    if (ElementCache.get('compileTime')) {
      fileUpdates.push({ element: ElementCache.get('compileTime'), operations: [(el) => DOMUtils.setText(el, d.compile_time || 'Unknown')] });
    }
    
    DOMUtils.batchUpdate(fileUpdates);

    // Render imports and blocks from backend data
    renderImports(d.critical_imports || '');
    renderBlocks(win10, win11, d);

    // Calculate and render score
    const score = calculateScore({ win10, win11, isLol, hasDanger });
    renderScore(score);
  }

  function renderHolyGrailBanner() {
    return `
      <div style="border: 1px solid var(--lb-sev-medium); padding: 12px 14px; display: flex; align-items: center; gap: 10px; background: rgba(234, 179, 8, 0.04);">
        <span class="lb-tag medium">⚑ HolyGrail</span>
        <div style="flex: 1;">
          <div class="lb-strong" style="font-size: 13px;">The Holy Grail Found</div>
          <div class="lb-muted" style="font-size: 11px;">Critical imports observed · Not on LOLDrivers · Not blocked</div>
        </div>
      </div>
    `;
  }

  function renderNeutralBanner(isLol, win10, win11, hasDanger) {
    let title, description;

    if (isLol) {
      title = 'Known Vulnerable Driver';
      description = 'Listed in LOLDrivers database';
    } else if (win10 || win11) {
      title = 'Blocked Driver';
      description = 'Listed on Microsoft recommended driver block rules';
    } else if (hasDanger) {
      title = 'Potentially Interesting';
      description = 'Contains critical imports but may have limited exploitation potential';
    } else {
      title = 'Low BYOVD Potential';
      description = 'No obvious signs of exploitation potential observed';
    }

    const severity = (isLol || win10 || win11) ? 'medium' : 'info';
    const borderColor = severity === 'medium'
        ? 'var(--lb-sev-medium)'
        : 'var(--lb-border-hi)';

    const statusDetails = [
      `LOLDrivers: ${isLol ? 'LISTED' : 'NOT LISTED'}`,
      `Win10: ${win10 ? 'BLOCKED' : 'ALLOWED'}`,
      `Win11: ${win11 ? 'BLOCKED' : 'ALLOWED'}`,
    ];

    return `
      <div style="border: 1px solid ${borderColor}; padding: 12px 14px;">
        <div class="lb-strong" style="font-size: 13px; margin-bottom: 4px;">${title}</div>
        <div class="lb-dim" style="font-size: 11px; margin-bottom: 6px;">${description}</div>
        <div class="lb-muted lb-mono" style="font-size: 10px;">${statusDetails.join(' · ')}</div>
      </div>
    `;
  }

  function renderImports(csv) {
    const wrap = ElementCache.get('importsWrap');
    clearAvNotes();
    
    if (!wrap) return;
    
    wrap.innerHTML = '';

    if (!csv || !csv.trim()) {
      wrap.innerHTML = '<span class="text-sm text-gray-500">No imports reported.</span>';
      DOMUtils.toggleClass(ElementCache.get('importsCard'), 'opacity-60', true);
      return;
    }

    DOMUtils.toggleClass(ElementCache.get('importsCard'), 'opacity-60', false);

    const avKeys = new Set(['ZwTerminateProcess','ZwOpenProcess','PsLookupProcessByProcessId']);
    const imports = csv.split(',').map(s => s.trim()).filter(Boolean);

    const low = csv.toLowerCase();
    const showAvNote = (low.includes('zwterminateprocess') &&
                       (low.includes('zwopenprocess') || low.includes('pslookupprocessbyprocessid')));

    if (showAvNote) {
      wrap.insertAdjacentHTML('beforebegin', `
        <div class="av-note bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-4">
          <div class="flex items-center gap-2 text-red-300 font-semibold mb-1">
            AV-killer capability: can terminate arbitrary process
          </div>
        </div>
      `);
    }

    // Use DocumentFragment for better performance
    const fragment = document.createDocumentFragment();
    imports.forEach(imp => {
      const hit = avKeys.has(imp);
      const span = document.createElement('span');
      span.className = hit ? 'lb-tag medium' : 'lb-tag info';
      span.textContent = imp;
      fragment.appendChild(span);
    });
    
    wrap.appendChild(fragment);
  }

  function renderBlocks(win10, win11, details) {
    const blocks = [
      {
        name: 'Windows 10',
        blocked: win10,
        reason: details.win10_block_reason || 'Status unknown',
        blockingDetails: details.win10_blocking_details
      },
      {
        name: 'Windows 11',
        blocked: win11,
        reason: details.win11_block_reason || 'Status unknown',
        blockingDetails: details.win11_blocking_details
      }
    ];

    DOMUtils.setHTML(ElementCache.get('blockRows'), blocks.map(block => {
      let detailsHtml = '';
      
      if (block.blocked && block.blockingDetails) {
        const bd = block.blockingDetails;
        detailsHtml = `
          <div style="margin-top: 10px; padding: 10px; border: 1px solid rgba(239, 68, 68, 0.25); background: rgba(239, 68, 68, 0.04);">
            <div style="display: flex; flex-direction: column; gap: 4px; font-size: 11px;">
              ${bd.blocked_signer_id ? `<div><span class="lb-eyebrow">Rule ID</span> <span class="lb-mono lb-strong">${escapeHTML(bd.blocked_signer_id)}</span></div>` : ''}
              ${bd.publisher_info ? `<div><span class="lb-eyebrow">Publisher</span> <span class="lb-strong">${escapeHTML(bd.publisher_info)}</span></div>` : ''}
              ${bd.matched_certificate?.thumbprint ? `<div><span class="lb-eyebrow">Cert Thumbprint</span> <code class="lb-mono lb-dim">${escapeHTML(bd.matched_certificate.thumbprint)}</code></div>` : ''}
              ${bd.matched_certificate?.tbs_sha1 ? `<div><span class="lb-eyebrow">TBS SHA1</span> <code class="lb-mono lb-dim">${escapeHTML(bd.matched_certificate.tbs_sha1)}</code></div>` : ''}
              ${bd.detailed_explanation ? `
                <details style="margin-top: 6px;">
                  <summary class="lb-accent" style="cursor: pointer; font-size: 11px;">Show detailed explanation</summary>
                  <pre class="lb-mono lb-dim" style="margin-top: 6px; font-size: 11px; white-space: pre-wrap; word-break: break-all;">${escapeHTML(bd.detailed_explanation)}</pre>
                </details>
              ` : ''}
            </div>
          </div>
        `;
      }

      return `
        <div style="border: 1px solid ${block.blocked ? 'rgba(239, 68, 68, 0.3)' : 'rgba(34, 197, 94, 0.3)'}; padding: 12px;">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
            <span class="lb-strong" style="font-size: 13px;">${block.name}</span>
            <span class="lb-tag ${block.blocked ? 'critical' : 'clean'}">${block.blocked ? 'Blocked' : 'Allowed'}</span>
          </div>
          <div class="lb-muted" style="font-size: 11px;">${escapeHTML(block.reason)}</div>
          ${detailsHtml}
        </div>
      `;
    }).join(''));
  }

  function calculateScore({ win10, win11, isLol, hasDanger }) {
    if (win11 && win10) return 0;

    let score = 0;
    if (hasDanger) score += 55;
    if (!win11) score += 25; else score -= 50;
    if (!win10) score += 20; else score -= 20;
    if (!isLol) score += 10; else score -= 5;

    return Math.max(0, Math.min(100, score));
  }

  function renderScore(score) {
    animateNumber(ElementCache.get('scoreValue'), 0, score, 1000);

    setTimeout(() => {
      const scoreBar = ElementCache.get('scoreBar');
      if (scoreBar) {
        requestAnimationFrame(() => {
          scoreBar.style.width = `${score}%`;
        });
      }
    }, 200);

    let label, cssVar;
    if (score >= 70) {
      label = 'HIGH';
      cssVar = 'var(--lb-sev-low)';      // high BYOVD potential = green for the operator
    } else if (score >= 40) {
      label = 'MEDIUM';
      cssVar = 'var(--lb-sev-medium)';
    } else {
      label = 'LOW';
      cssVar = 'var(--lb-text-mute)';
    }

    const scoreLabel = ElementCache.get('scoreLabel');
    if (scoreLabel) {
      DOMUtils.setText(scoreLabel, `BYOVD Potential: ${label}`);
      scoreLabel.style.color = cssVar;
      scoreLabel.style.fontSize = '11px';
    }
  }

  function updateBadge(element, text, type) {
    const colors = {
      success: 'var(--lb-sev-low)',
      danger:  'var(--lb-accent)',
      warning: 'var(--lb-sev-medium)',
      info:    'var(--lb-text-dim)',
    };
    
    if (element) {
      DOMUtils.setText(element, text);
      element.style.color = colors[type] || 'var(--lb-text)';
      element.style.fontSize = '12px';
    }
  }

  // ====== Optimized Stepper Control ======
  function hideStepper() {
    const stepper = ElementCache.get('stepper');
    if (stepper) {
      DOMUtils.toggleClass(stepper, 'analysis-complete', true);
      setTimeout(() => {
        DOMUtils.toggleClass(stepper, 'hidden', true);
      }, 300);
    }
  }

  function showStepper() {
    const stepper = ElementCache.get('stepper');
    if (stepper) {
      DOMUtils.toggleClass(stepper, 'hidden', false);
      DOMUtils.toggleClass(stepper, 'analysis-complete', false);
    }
  }

  // ====== Optimized UI Functions ======
  function markStep(circle, state) {
    if (!circle) return;

    // Preserve the base hg-step-circle class from the template; just toggle
    // active/done modifiers.
    circle.classList.remove('active', 'done', 'idle');
    if (state) circle.classList.add(state);

    if (state === 'done') {
      circle.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="20,6 9,17 4,12"/>
        </svg>
      `;
    } else {
      circle.textContent = circle.getAttribute('data-step') || circle.textContent;
    }
  }

  function progress(percent) {
    const progressBar = ElementCache.get('progressBar');
    if (progressBar) {
      requestAnimationFrame(() => {
        progressBar.style.width = `${Math.max(0, Math.min(100, percent))}%`;
      });
    }
  }

  function clearConsole() {
    const consoleLog = ElementCache.get('consoleLog');
    if (consoleLog) {
      consoleLog.innerHTML = '';
    }
  }

  function log(message) {
    const consoleLog = ElementCache.get('consoleLog');
    if (!consoleLog) return;
    
    // Single <li>; the .hg-console-log CSS prefixes each line with `>`.
    const line = document.createElement('li');
    line.textContent = message;
    consoleLog.appendChild(line);
    
    // Smooth scroll to bottom using requestAnimationFrame
    requestAnimationFrame(() => {
      consoleLog.scrollTop = consoleLog.scrollHeight;
    });
  }

  function hardReset() {
    abort = true;
    analysisComplete = false;
    
    fadeOut(ElementCache.get('resultsCard'));
    fadeOut(ElementCache.get('consoleCard'));
    setTimeout(() => {
      fadeIn(ElementCache.get('uploadCard'));
      showStepper();
    }, 300);
    
    progress(0);
    clearConsole();
    
    markStep(ElementCache.get('s1'), 'active');
    markStep(ElementCache.get('s2'), 'idle');
    markStep(ElementCache.get('s3'), 'idle');
    
    // Batch reset operations for better performance
    const resetData = {
      'summaryName': 'No file',
      'summaryType': '—',
      'summaryTime': '—',
      'sha256Full': 'Unknown',
      'fileVersion': 'Unknown',
      'fileSizePretty': 'Unknown',
      'arch': 'Unknown'
    };
    
    if (ElementCache.get('originalFilename')) {
      resetData['originalFilename'] = 'Unknown';
    }
    
    const resetUpdates = Object.entries(resetData).map(([id, value]) => ({
      element: ElementCache.get(id),
      operations: [(el) => DOMUtils.setText(el, value)]
    }));
    
    DOMUtils.batchUpdate(resetUpdates);
    
    updateBadge(ElementCache.get('lolBadge'), 'LOL?', 'info');
    updateBadge(ElementCache.get('w10Badge'), 'Win10', 'info');
    updateBadge(ElementCache.get('w11Badge'), 'Win11', 'info');
    
    // Clear containers
    const containers = ['verdictBanner', 'importsWrap', 'blockRows'];
    containers.forEach(id => {
      const element = ElementCache.get(id);
      if (element) element.innerHTML = '';
    });
    
    renderScore(0);
    
    currentHash = null;
    currentName = null;
    abort = false;
  }

  // ====== Optimized Animation Functions ======
  function fadeIn(element) {
    if (!element) return;
    
    DOMUtils.toggleClass(element, 'hidden', false);
    element.style.opacity = '0';
    AnimationUtils.translate3d(element, 0, 10, 0);
    
    requestAnimationFrame(() => {
      element.style.transition = 'all 0.3s ease';
      element.style.opacity = '1';
      AnimationUtils.translate3d(element, 0, 0, 0);
      
      setTimeout(() => {
        element.style.transition = '';
        element.style.transform = '';
      }, 300);
    });
  }

  function fadeOut(element, callback) {
    if (!element) return;
    
    element.style.transition = 'all 0.3s ease';
    element.style.opacity = '0';
    AnimationUtils.translate3d(element, 0, -10, 0);
    
    setTimeout(() => {
      DOMUtils.toggleClass(element, 'hidden', true);
      element.style.opacity = '';
      element.style.transform = '';
      element.style.transition = '';
      if (callback) callback();
    }, 300);
  }

  function animateNumber(element, start, end, duration) {
    if (!element) return;
    
    const startTime = performance.now();
    
    function update(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      const easeOut = AnimationUtils.easeOutCubic(progress);
      const current = Math.round(start + (end - start) * easeOut);
      
      DOMUtils.setText(element, current.toString());
      
      if (progress < 1) {
        requestAnimationFrame(update);
      }
    }
    
    requestAnimationFrame(update);
  }

  // ====== Optimized Toast System ======
  function toast(message, type = 'info') {
    const accent = {
      success: 'var(--lb-sev-low)',
      error:   'var(--lb-accent)',
      warning: 'var(--lb-sev-medium)',
      info:    'var(--lb-text-mute)',
    }[type] || 'var(--lb-text-mute)';

    const icons = {
      success: 'M20,6 9,17 4,12',
      error:   'M18,6 6,18 M6,6 18,18',
      warning: 'M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z M12,9 12,13 M12,17 12.01,17',
      info:    'M12,2 12,6 M12,10 12.01,10 M21,12 A9,9 0 1,1 3,12 A9,9 0 1,1 21,12',
    };

    const toast = document.createElement('div');
    toast.style.cssText = `
      background: var(--lb-panel); color: var(--lb-text);
      border: 1px solid ${accent}; border-left: 3px solid ${accent};
      padding: 10px 14px; max-width: 360px; font-size: 12px;
      box-shadow: 0 8px 24px rgba(0,0,0,0.5);
      display: flex; align-items: center; gap: 10px;
      transition: opacity 0.3s ease;
    `;
    toast.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="${accent}" stroke-width="2" style="flex-shrink: 0;">
        <path d="${icons[type] || icons.info}"/>
      </svg>
      <span>${escapeHTML(message)}</span>
    `;

    ElementCache.get('toastContainer')?.appendChild(toast);

    setTimeout(() => {
      if (toast.parentElement) {
        toast.style.opacity = '0';
        AnimationUtils.translate3d(toast, 100, 0, 0);
        setTimeout(() => toast.remove(), 300);
      }
    }, HOLYGRAIL.toastMs);
  }

  // ====== Optimized Utility Functions ======
  function normalize(raw) {
    const findings = raw?.findings || raw || {};
    return {
      summary: findings.summary || {},
      detailed: findings.detailed_analysis || {}
    };
  }

  function isAllowed(name) {
    const ext = extName(name).toLowerCase();
    return HOLYGRAIL.allowed.includes(ext);
  }

  function extName(name) {
    return (name || '').split('.').pop() || '';
  }

  function prettySize(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 Bytes';
    const units = ['Bytes', 'KB', 'MB', 'GB'];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return `${parseFloat((bytes / Math.pow(1024, index)).toFixed(2))} ${units[index]}`;
  }

  function prettyTime(timestamp) {
    return new Date(timestamp || Date.now()).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  }

  function prevent(e) {
    e.preventDefault();
    e.stopPropagation();
  }

  // escapeHTML is a local alias for the shared util to keep call sites unchanged.
  const escapeHTML = escapeHtml;

  function jsonOrThrow(response) {
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    return response.json();
  }

  function clearAvNotes() {
    ElementCache.get('importsCard')?.querySelectorAll('.av-note').forEach(n => n.remove());
  }

  // ====== Initialize Application ======
  hardReset();
});