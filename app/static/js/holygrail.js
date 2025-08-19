// app/static/js/holygrail.js

// ===== Performance-Optimized HolyGrail BYOVD Analysis Tool =====
const HOLYGRAIL = {
  maxFileSize: 100 * 1024 * 1024,
  allowed: ['sys','dll','exe','bin'],
  toastMs: 4000,
  stepDurationMs: 400,
};

// Performance-optimized DOM element cache
const ElementCache = {
  cache: new Map(),
  
  get(id) {
    if (!this.cache.has(id)) {
      const element = document.getElementById(id);
      if (element) {
        this.cache.set(id, element);
      }
    }
    return this.cache.get(id);
  },
  
  // Pre-cache critical elements
  preCache(ids) {
    const fragment = document.createDocumentFragment();
    ids.forEach(id => this.get(id));
  },
  
  clear() {
    this.cache.clear();
  }
};

// Performance-optimized animation utilities
const AnimationUtils = {
  // Use requestAnimationFrame for smooth animations
  animate(element, properties, duration = 300, easing = 'ease') {
    return new Promise(resolve => {
      if (!element) {
        resolve();
        return;
      }
      
      const startTime = performance.now();
      const startValues = {};
      const endValues = {};
      
      // Parse properties and get initial values
      Object.keys(properties).forEach(prop => {
        const computed = getComputedStyle(element);
        startValues[prop] = parseFloat(computed[prop]) || 0;
        endValues[prop] = parseFloat(properties[prop]);
      });
      
      const tick = (currentTime) => {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Apply easing (simplified cubic-bezier)
        const easedProgress = this.easeOutCubic(progress);
        
        // Update properties
        Object.keys(properties).forEach(prop => {
          const current = startValues[prop] + (endValues[prop] - startValues[prop]) * easedProgress;
          element.style[prop] = `${current}${this.getUnit(prop)}`;
        });
        
        if (progress < 1) {
          requestAnimationFrame(tick);
        } else {
          resolve();
        }
      };
      
      requestAnimationFrame(tick);
    });
  },
  
  easeOutCubic(t) {
    return 1 - Math.pow(1 - t, 3);
  },
  
  getUnit(property) {
    const unitProperties = ['width', 'height', 'top', 'left', 'right', 'bottom'];
    return unitProperties.includes(property) ? 'px' : '';
  },
  
  // GPU-accelerated transforms
  translate3d(element, x = 0, y = 0, z = 0) {
    if (element) {
      element.style.transform = `translate3d(${x}px, ${y}px, ${z}px)`;
    }
  },
  
  scale3d(element, x = 1, y = 1, z = 1) {
    if (element) {
      element.style.transform = `scale3d(${x}, ${y}, ${z})`;
    }
  }
};

// Optimized DOM utilities
const DOMUtils = {
  // Batch DOM updates to reduce reflows
  batchUpdate(updates) {
    const fragment = document.createDocumentFragment();
    
    // Temporarily detach elements to avoid multiple reflows
    updates.forEach(({ element, operations }) => {
      if (element && element.parentNode) {
        const parent = element.parentNode;
        const nextSibling = element.nextSibling;
        parent.removeChild(element);
        
        operations.forEach(op => op(element));
        
        parent.insertBefore(element, nextSibling);
      }
    });
  },
  
  // Optimized class management
  toggleClass(element, className, force) {
    if (element) {
      if (force !== undefined) {
        element.classList.toggle(className, force);
      } else {
        element.classList.toggle(className);
      }
    }
  },
  
  // Efficient text content updates
  setText(element, text) {
    if (element && element.textContent !== text) {
      element.textContent = text;
    }
  },
  
  // Efficient HTML updates with DocumentFragment
  setHTML(element, html) {
    if (element) {
      element.innerHTML = html;
    }
  }
};

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
      <div class="verdict-holy">
        <div class="flex items-center gap-3 mb-3">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-yellow-400 to-orange-500 flex items-center justify-center shadow-lg">
            <svg class="w-6 h-6 text-white" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/>
            </svg>
          </div>
          <div>
            <h3 class="text-xl font-bold text-yellow-300 flex items-center gap-2">
              The Holy Grail Found
            </h3>
            <p class="text-yellow-200/80 text-sm">Dangerous imports detected • Not on LOLDrivers • Not blocked</p>
          </div>
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
      description = 'Contains suspicious imports but may have limited exploitation potential';
    } else {
      title = 'Low Risk Driver';
      description = 'No obvious signs of exploitation potential detected';
    }
    
    const severity = (isLol || win10 || win11) ? 'warning' : 'info';
    const colors = {
      warning: 'border-yellow-500/30 bg-yellow-500/10',
      info: 'border-blue-500/30 bg-blue-500/10'
    };

    const statusDetails = [];
    if (isLol) statusDetails.push('LOLDrivers: LISTED');
    else statusDetails.push('LOLDrivers: NOT LISTED');
    
    if (win10) statusDetails.push('Win10: BLOCKED');
    else statusDetails.push('Win10: ALLOWED');
    
    if (win11) statusDetails.push('Win11: BLOCKED');  
    else statusDetails.push('Win11: ALLOWED');

    return `
      <div class="verdict-neutral ${colors[severity]} border rounded-xl p-4">
        <h3 class="text-lg font-semibold text-white mb-1">${title}</h3>
        <p class="text-sm text-gray-300 mb-2">${description}</p>
        <div class="text-xs text-gray-400">
          ${statusDetails.join(' • ')}
        </div>
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
      const cls = hit ? 'cyber-chip success' : 'cyber-chip';
      const span = document.createElement('span');
      span.className = cls;
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
          <div class="mt-3 p-3 bg-red-500/5 border border-red-500/20 rounded-lg">
            <div class="text-xs space-y-2">
              ${bd.blocked_signer_id ? `<div><strong>Rule ID:</strong> ${escapeHTML(bd.blocked_signer_id)}</div>` : ''}
              ${bd.publisher_info ? `<div><strong>Publisher:</strong> ${escapeHTML(bd.publisher_info)}</div>` : ''}
              ${bd.matched_certificate?.thumbprint ? `<div><strong>Cert Thumbprint:</strong> <code class="text-xs">${escapeHTML(bd.matched_certificate.thumbprint)}</code></div>` : ''}
              ${bd.matched_certificate?.tbs_sha1 ? `<div><strong>TBS SHA1:</strong> <code class="text-xs">${escapeHTML(bd.matched_certificate.tbs_sha1)}</code></div>` : ''}
              ${bd.detailed_explanation ? `
                <details class="mt-2">
                  <summary class="cursor-pointer text-red-300 hover:text-red-200">Show detailed explanation</summary>
                  <pre class="mt-2 text-xs text-gray-300 whitespace-pre-wrap">${escapeHTML(bd.detailed_explanation)}</pre>
                </details>
              ` : ''}
            </div>
          </div>
        `;
      }
      
      return `
        <div class="cyber-card p-4 ${block.blocked ? 'border-red-500/30' : 'border-green-500/30'}">
          <div class="flex items-center justify-between mb-2">
            <h5 class="font-medium text-white">${block.name}</h5>
            <span class="cyber-chip ${block.blocked ? 'danger' : 'success'}">
              ${block.blocked ? 'BLOCKED' : 'ALLOWED'}
            </span>
          </div>
          <p class="text-xs text-gray-400 mb-1">${escapeHTML(block.reason)}</p>
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

    let label, color;
    if (score >= 70) {
      label = 'HIGH';
      color = 'text-green-300';
    } else if (score >= 40) {
      label = 'MEDIUM';
      color = 'text-yellow-300';
    } else {
      label = 'LOW';
      color = 'text-red-300';
    }

    const scoreLabel = ElementCache.get('scoreLabel');
    if (scoreLabel) {
      DOMUtils.setText(scoreLabel, `BYOVD Potential: ${label}`);
      scoreLabel.className = `text-sm font-medium ${color}`;
    }
  }

  function updateBadge(element, text, type) {
    const colors = {
      success: 'text-green-300',
      danger: 'text-red-300',
      warning: 'text-yellow-300',
      info: 'text-blue-300'
    };
    
    if (element) {
      DOMUtils.setText(element, text);
      element.className = `text-sm font-medium ${colors[type] || 'text-gray-300'}`;
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
    
    circle.className = `step-circle ${state}`;
    
    if (state === 'done') {
      circle.innerHTML = `
        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
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
    
    // Use DocumentFragment for better performance
    const fragment = document.createDocumentFragment();
    const line = document.createElement('li');
    line.className = 'console-line';
    line.innerHTML = `
      <div class="dot"></div>
      <span>${escapeHTML(message)}</span>
    `;
    fragment.appendChild(line);
    consoleLog.appendChild(fragment);
    
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
    const colors = {
      success: 'border-green-500/30 bg-green-500/10 text-green-300',
      error: 'border-red-500/30 bg-red-500/10 text-red-300',
      warning: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-300',
      info: 'border-blue-500/30 bg-blue-500/10 text-blue-300'
    };

    const icons = {
      success: 'M20,6 9,17 4,12',
      error: 'M18,6 6,18 M6,6 18,18',
      warning: 'M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z M12,9 12,13 M12,17 12.01,17',
      info: 'M12,2 12,6 M12,10 12.01,10 M21,12 A9,9 0 1,1 3,12 A9,9 0 1,1 21,12'
    };

    const toast = document.createElement('div');
    toast.className = `toast flex items-center gap-3 ${colors[type]}`;
    toast.innerHTML = `
      <svg class="w-5 h-5 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="${icons[type]}"/>
      </svg>
      <span class="font-medium">${escapeHTML(message)}</span>
    `;

    ElementCache.get('toastContainer')?.appendChild(toast);

    setTimeout(() => {
      if (toast.parentElement) {
        toast.style.transition = 'all 0.3s ease';
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

  function escapeHTML(str) {
    return (str ?? '').toString()
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

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