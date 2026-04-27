// app/static/js/holygrail/utils.js
// Performance-oriented helpers for the HolyGrail page:
// HOLYGRAIL config, ElementCache, AnimationUtils, DOMUtils.

// app/static/js/holygrail.js

// ===== Performance-Optimized HolyGrail BYOVD Analysis Tool =====
export const HOLYGRAIL = {
  maxFileSize: 100 * 1024 * 1024,
  allowed: ['sys','dll','exe','bin'],
  toastMs: 4000,
  stepDurationMs: 400,
};

// Performance-optimized DOM element cache
export const ElementCache = {
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
export const AnimationUtils = {
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
export const DOMUtils = {
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
