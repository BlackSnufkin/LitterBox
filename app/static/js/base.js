// app/static/js/base.js
//
// Loaded as an ES module by base.html. Module strict mode means top-level
// `function foo() {}` no longer auto-globalises; we explicitly attach every
// name that templates reference via inline `onclick="..."` handlers to
// `window` at the bottom of this file.
//
// The hybrid terminal layout has no collapse-sidebar control, so this file
// is leaner than the previous version: only status checking, modals,
// notifications, and the inline-handler shims.

const CONFIG = {
    notificationDuration: 5000,
    fadeDelay: 300,
    modalFocusDelay: 100,
};

// ----------------------------------------------------------------------
// Status manager — drives the sidebar footer status dot + issues popover
// ----------------------------------------------------------------------
class StatusManager {
    constructor() {
        if (window._statusManagerInstance) {
            return window._statusManagerInstance;
        }
        window._statusManagerInstance = this;

        this.hasCheckedStatus = sessionStorage.getItem('statusChecked') === 'true';

        this.elements = {
            indicator: document.getElementById('status-indicator'),
            text:      document.getElementById('status-text'),
            container: document.querySelector('.lb-sidebar-foot'),
            popover:   document.getElementById('issues-popover'),
            issuesList: document.getElementById('issues-list'),
        };

        this.state = {
            isPopoverVisible: false,
            currentIssues: [],
        };

        if (this.hasCheckedStatus) {
            this.setActiveState();
        }

        this.handleClickOutside = this.handleClickOutside.bind(this);
    }

    init() {
        if (!this.hasCheckedStatus) {
            this.checkStatus();
            sessionStorage.setItem('statusChecked', 'true');
            this.hasCheckedStatus = true;
        }
        document.addEventListener('click', this.handleClickOutside);
    }

    async checkStatus() {
        try {
            const response = await fetch('/health');
            const data = await response.json();

            if (data.status === 'ok') {
                this.setActiveState();
            } else {
                this.setDegradedState(data.issues || []);
            }
        } catch (error) {
            this.handleError(error);
        }
    }

    setIndicatorClass(state) {
        const { indicator } = this.elements;
        if (!indicator) return;
        indicator.classList.remove('ok', 'warn', 'fail');
        if (state) indicator.classList.add(state);
    }

    setActiveState() {
        const { text, container } = this.elements;
        this.setIndicatorClass('ok');
        if (text) {
            text.textContent = 'Active';
            text.style.color = 'var(--lb-sev-low)';
        }
        if (container) container.style.cursor = 'default';
        this.hidePopover();
        this.removeClickHandler();
    }

    setDegradedState(issues) {
        const { text } = this.elements;
        this.setIndicatorClass('fail');
        if (text) {
            text.textContent = 'Degraded';
            text.style.color = 'var(--lb-accent)';
        }
        if (issues && issues.length > 0) {
            this.state.currentIssues = issues;
            this.updateIssuesDisplay(issues);
            this.setupClickHandler();
        }
    }

    updateIssuesDisplay(issues) {
        const { issuesList, container } = this.elements;
        if (issuesList) {
            issuesList.innerHTML = '';
            issues.forEach(issue => {
                const li = document.createElement('li');
                li.textContent = issue;
                issuesList.appendChild(li);
            });
        }
        if (container) container.style.cursor = 'pointer';
    }

    handleError(error) {
        const { text } = this.elements;
        this.setIndicatorClass('fail');
        if (text) {
            text.textContent = 'Error';
            text.style.color = 'var(--lb-accent)';
        }
        const message = error.message.includes('Failed to fetch')
            ? 'Cannot connect to server. Please check your connection.'
            : error.message;
        this.updateIssuesDisplay([message]);
        this.setupClickHandler();
    }

    setupClickHandler() {
        const { container } = this.elements;
        this.removeClickHandler();
        if (container) {
            container.onclick = (e) => {
                e.stopPropagation();
                this.togglePopover();
            };
        }
    }

    removeClickHandler() {
        const { container } = this.elements;
        if (container) container.onclick = null;
    }

    togglePopover() {
        this.state.isPopoverVisible ? this.hidePopover() : this.showPopover();
    }

    showPopover() {
        const { popover } = this.elements;
        if (!popover) return;
        popover.classList.remove('hidden');
        this.state.isPopoverVisible = true;
    }

    hidePopover() {
        const { popover } = this.elements;
        if (!popover) return;
        popover.classList.add('hidden');
        this.state.isPopoverVisible = false;
    }

    handleClickOutside(event) {
        const { container } = this.elements;
        if (this.state.isPopoverVisible && container && !container.contains(event.target)) {
            this.hidePopover();
        }
    }
}

// ----------------------------------------------------------------------
// Navigation helpers
// ----------------------------------------------------------------------
function showSummary()       { window.location.href = '/summary'; }
function openDoppelganger()  { window.location.href = '/doppelganger'; }

// ----------------------------------------------------------------------
// Notifications
// ----------------------------------------------------------------------
const NotificationSystem = {
    show(message, severity = 'info', duration = CONFIG.notificationDuration) {
        const colorMap = {
            success: 'var(--lb-sev-low)',
            warn:    'var(--lb-sev-medium)',
            error:   'var(--lb-accent)',
            info:    'var(--lb-text-mute)',
        };
        // Back-compat: callers used to pass Tailwind class names like 'bg-red-500'.
        if (severity.startsWith('bg-')) {
            severity = severity.includes('green') ? 'success'
                     : severity.includes('yellow') ? 'warn'
                     : severity.includes('red')    ? 'error' : 'info';
        }
        const color = colorMap[severity] || colorMap.info;

        const note = document.createElement('div');
        note.style.cssText = `
            position: fixed; top: 16px; right: 16px;
            background: var(--lb-panel); color: var(--lb-text);
            border: 1px solid ${color}; border-left: 3px solid ${color};
            padding: 10px 14px; max-width: 400px; z-index: 200;
            font-size: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.5);
            transition: opacity ${CONFIG.fadeDelay}ms ease;
        `;
        const wrap = document.createElement('div');
        wrap.style.cssText = 'display: flex; gap: 12px; align-items: flex-start;';

        const msg = document.createElement('div');
        msg.style.whiteSpace = 'pre-line';
        msg.style.flex = '1';
        msg.textContent = message;

        const close = document.createElement('button');
        close.innerHTML = '&times;';
        close.style.cssText = `
            background: transparent; border: 0; color: var(--lb-text-mute);
            cursor: pointer; font-size: 18px; line-height: 1; padding: 0 4px;
        `;
        close.onclick = () => this.dismiss(note);

        wrap.appendChild(msg);
        wrap.appendChild(close);
        note.appendChild(wrap);
        document.body.appendChild(note);

        setTimeout(() => {
            if (document.body.contains(note)) this.dismiss(note);
        }, duration);
    },

    dismiss(note) {
        note.style.opacity = '0';
        setTimeout(() => note.remove(), CONFIG.fadeDelay);
    },
};

// ----------------------------------------------------------------------
// Modal management
// ----------------------------------------------------------------------
const ModalManager = {
    showProcessWarning() {
        const modal = document.getElementById('processWarningModal');
        if (!modal) return;
        modal.classList.remove('hidden');
        setTimeout(() => document.getElementById('processId')?.focus(), CONFIG.modalFocusDelay);
    },
    hideProcessWarning() {
        document.getElementById('processWarningModal')?.classList.add('hidden');
    },
    showCleanupWarning() {
        document.getElementById('cleanupWarningModal')?.classList.remove('hidden');
    },
    hideCleanupWarning() {
        document.getElementById('cleanupWarningModal')?.classList.add('hidden');
    },
};

// ----------------------------------------------------------------------
// Process analysis trigger
// ----------------------------------------------------------------------
const ProcessManager = {
    validatePID(pid) {
        if (!pid) return { isValid: false, error: 'Please enter a process ID' };
        if (!/^\d+$/.test(pid)) return { isValid: false, error: 'PID must be a positive number' };
        if (parseInt(pid, 10) <= 0) return { isValid: false, error: 'PID must be greater than 0' };
        return { isValid: true };
    },

    async startAnalysis() {
        const pid = document.getElementById('processId')?.value;
        const validation = this.validatePID(pid);
        if (!validation.isValid) {
            NotificationSystem.show(validation.error, 'error');
            return;
        }

        const button = this.updateButton('Validating…');
        try {
            const response = await fetch(`/validate/${pid}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(this.getErrorMessage(response.status, pid, data));
            }

            ModalManager.hideProcessWarning();
            NotificationSystem.show(`Starting analysis of process ${pid}…`, 'success');
            window.location.href = `/analyze/dynamic/${pid}`;
        } catch (error) {
            console.error('Process analysis error:', error);
            NotificationSystem.show(error.message, 'error');
        } finally {
            this.resetButton(button);
        }
    },

    getErrorMessage(status, pid, data) {
        switch (status) {
            case 404: return `Process ID ${pid} not found. Please verify the PID and try again.`;
            case 403: return `Access denied to process ${pid}. Please check permissions.`;
            default:  return data.error || 'Unknown error occurred';
        }
    },

    updateButton(text) {
        const btn = document.querySelector('[onclick="startProcessAnalysis()"]');
        if (btn) { btn.disabled = true; btn.textContent = text; }
        return btn;
    },

    resetButton(btn) {
        if (btn) { btn.disabled = false; btn.textContent = 'Start Analysis'; }
    },
};

// ----------------------------------------------------------------------
// Cleanup
// ----------------------------------------------------------------------
const CleanupSystem = {
    async execute() {
        ModalManager.hideCleanupWarning();
        try {
            const response = await fetch('/cleanup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            });
            const data = await response.json();
            const { message, severity } = this.formatResponse(data);
            NotificationSystem.show(message, severity);
        } catch (error) {
            NotificationSystem.show(`Error during cleanup: ${error.message}`, 'error');
        }
    },

    formatResponse(data) {
        if (data.status === 'success') {
            return {
                message: `Cleanup successful:\n- ${data.details.uploads_cleaned} uploaded files removed\n- ${data.details.analysis_cleaned} analysis results cleaned (PE-Sieve, HolyGrail)\n- ${data.details.result_cleaned} result folders cleaned\n- Doppelganger database cleaned`,
                severity: 'success',
            };
        }
        if (data.status === 'warning') {
            return {
                message: `Cleanup completed with warnings:\n- ${data.details.uploads_cleaned} uploaded files removed\n- ${data.details.analysis_cleaned} analysis results cleaned\n- ${data.details.result_cleaned} result folders cleaned\n\nErrors:\n${data.details.errors.join('\n')}`,
                severity: 'warn',
            };
        }
        return {
            message: `Cleanup failed: ${data.message || data.error}`,
            severity: 'error',
        };
    },
};

// ----------------------------------------------------------------------
// Init
// ----------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    const statusManager = new StatusManager();
    statusManager.init();

    document.getElementById('processWarningModal')?.addEventListener('click', (e) => {
        if (e.target.id === 'processWarningModal') ModalManager.hideProcessWarning();
    });
    document.getElementById('cleanupWarningModal')?.addEventListener('click', (e) => {
        if (e.target.id === 'cleanupWarningModal') ModalManager.hideCleanupWarning();
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            ModalManager.hideProcessWarning();
            ModalManager.hideCleanupWarning();
        }
    });
});

// ----------------------------------------------------------------------
// Export to window — referenced by inline onclick handlers in templates
// ----------------------------------------------------------------------
window.showProcessWarning   = ModalManager.showProcessWarning.bind(ModalManager);
window.hideProcessWarning   = ModalManager.hideProcessWarning.bind(ModalManager);
window.startProcessAnalysis = ProcessManager.startAnalysis.bind(ProcessManager);
window.showCleanupWarning   = ModalManager.showCleanupWarning.bind(ModalManager);
window.hideCleanupWarning   = ModalManager.hideCleanupWarning.bind(ModalManager);
window.executeCleanup       = CleanupSystem.execute.bind(CleanupSystem);
window.cleanupSystem        = ModalManager.showCleanupWarning.bind(ModalManager);
window.showNotification     = NotificationSystem.show.bind(NotificationSystem);
window.showSummary          = showSummary;
window.openDoppelganger     = openDoppelganger;
