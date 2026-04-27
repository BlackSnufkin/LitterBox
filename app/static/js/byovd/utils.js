// app/static/js/byovd/utils.js
// Page-local helpers: PERF_CONFIG, ElementCache, DOMUtils, AnimationSystem.
// (APIClient lives in api.js; the ByovdApp class lives in core.js.)

// ===== PERFORMANCE CONSTANTS =====
export const PERF_CONFIG = {
  CACHE_TTL: 300000, // 5 minutes
  ANIMATION_DURATION: 800,
  FRAME_BUDGET: 16, // 16ms for 60fps
  BATCH_SIZE: 50,
  DEBOUNCE_DELAY: 100
};

// ===== MEMORY-EFFICIENT ELEMENT CACHE =====
export class ElementCache {
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
export class DOMUtils {
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

// ===== OPTIMIZED ANIMATION SYSTEM =====
export class AnimationSystem {
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

