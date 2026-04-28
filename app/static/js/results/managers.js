// app/static/js/results/managers.js
// UI managers attached on DOMContentLoaded.

// Tab Manager
export class TabManager {
    constructor() {
        this.tabs = document.querySelectorAll('.tab-button');
        this.tabContents = document.querySelectorAll('.tab-content');
        this.setupTabs();
    }

    setupTabs() {
        this.tabs.forEach(tab => {
            tab.addEventListener('click', () => this.switchTab(tab));
        });

        // Activate first tab by default
        if (this.tabs.length > 0) {
            this.tabs[0].click();
        }
    }

    switchTab(selectedTab) {
        const target = selectedTab.dataset.tab;

        // Hide all tab content and deactivate tabs
        this.tabContents.forEach(content => content.classList.add('hidden'));
        this.tabs.forEach(tab => tab.classList.remove('active'));

        // Show target content and activate tab
        document.getElementById(target).classList.remove('hidden');
        selectedTab.classList.add('active');
    }
}

// Payload Manager Class
export class PayloadManager {
    constructor() {
        this.toggleBtn = document.getElementById('togglePayloadOutput');
        this.content = document.getElementById('payloadOutputContent');
        this.chevron = document.getElementById('payloadChevron');
        this.stdout = document.getElementById('payloadStdout');
        this.stderr = document.getElementById('payloadStderr');
        this.stdoutSection = document.getElementById('stdoutSection');
        this.stderrSection = document.getElementById('stderrSection');
        this.info = document.getElementById('payloadOutputInfo');
        this.status = document.getElementById('payloadOutputStatus');

        this.setupToggle();
    }

    setupToggle() {
        if (this.toggleBtn && this.content && this.chevron) {
            this.toggleBtn.addEventListener('click', () => {
                this.content.classList.toggle('hidden');
                this.chevron.classList.toggle('rotate-90');
            });
        }
    }

    updatePayloadOutput(results) {
        if (!results.process_output) return;

        const { stdout, stderr, output_truncated, exit_code } = results.process_output;

        // Update stdout
        if (stdout && this.stdout && this.stdoutSection) {
            this.stdout.textContent = stdout;
            this.stdoutSection.classList.remove('hidden');
        }

        // Update stderr
        if (stderr && this.stderr && this.stderrSection) {
            this.stderr.textContent = stderr;
            this.stderrSection.classList.remove('hidden');
        }

        // Update status badge
        if (stdout || stderr) {
            this.status.textContent = 'Output Available';
            this.status.classList.remove('muted');
            this.status.classList.add('clean');
        } else {
            this.status.textContent = 'No Process Output';
        }

        // Add additional info
        if (this.info) {
            const infoText = [];
            if (output_truncated) {
                infoText.push('Output was truncated due to size limitations');
            }
            if (exit_code !== null) {
                infoText.push(`Process exit code: ${exit_code}`);
            }
            this.info.textContent = infoText.join(' • ');
        }
    }
}

// Analysis Type Handler
export class AnalysisTypeHandler {
    constructor() {
        this.setupAnalysisType();
    }

    isNumeric(str) {
        return /^\d+$/.test(str);
    }

    setupAnalysisType() {
        const pathSegments = window.location.pathname.split('/').filter(segment => segment.length > 0);
        const identifier = pathSegments[pathSegments.length - 1];
        
        // If PID, hide static analysis button
        if (this.isNumeric(identifier)) {
            const staticButton = document.getElementById('staticAnalysisButton');
            if (staticButton) {
                staticButton.style.display = 'none';
            }
        }
    }
}

// Modal Handler — used on the static results page to confirm jumping to
// dynamic analysis. The dynamic results page doesn't render this modal at
// all, so every member is null-guarded.
export class ModalHandler {
    constructor() {
        this.modal = document.getElementById('dynamicWarningModal');
        this.dialog = this.modal ? this.modal.querySelector('.lb-modal') : null;
        this.setupListeners();
    }

    setupListeners() {
        if (!this.modal) return;
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) this.hide();
        });
    }

    show() {
        if (!this.modal) return;
        this.modal.classList.remove('hidden');
    }

    hide() {
        if (!this.modal) return;
        this.modal.classList.add('hidden');
    }
}
