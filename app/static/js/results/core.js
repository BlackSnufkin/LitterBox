// app/static/js/results/core.js
// Entry point for the /results/<analysis_type>/<target> page.
// Wires up TabManager, PayloadManager, AnalysisTypeHandler, ModalHandler
// and the AnalysisCore poll loop.

import { TabManager, PayloadManager, AnalysisTypeHandler, ModalHandler } from './managers.js';
import { UI } from './renderers.js';
import { tools } from './tools.js';

// Analysis Core Logic
class AnalysisCore {
    constructor() {
        this.elements = {
            analysisStatus: document.getElementById('analysisStatus'),
            statusIcon: document.getElementById('statusIcon'),
            analysisTimer: document.getElementById('analysisTimer'),
            stageLine: document.getElementById('stageLine'),
            analysisStage: document.getElementById('analysisStage')
        };
        this.startTime = Date.now();
        this.timerInterval = null;

        const pathParts = window.location.pathname.split('/');
        this.analysisType = pathParts[2];
        // Static/dynamic: /analyze/<type>/<hash>           — hash at index 3.
        // EDR:           /analyze/edr/<profile>/<hash>     — hash at index 4
        // and profile at index 3 (used by the renderer to label the run).
        this.fileHash = pathParts[pathParts.length - 1];
        this.edrProfile = this.analysisType === 'edr' ? pathParts[3] : null;
    }

    updateTimer() {
        const elapsed = Date.now() - this.startTime;
        const minutes = Math.floor(elapsed / 60000);
        const seconds = Math.floor((elapsed % 60000) / 1000);
        const milliseconds = elapsed % 1000;
        this.elements.analysisTimer.textContent = 
            `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}.${milliseconds.toString().padStart(3, '0')}`;
        // Update summary scan duration
        document.getElementById('scanDuration').textContent = this.elements.analysisTimer.textContent;
    }
    startTimer() {
        this.timerInterval = setInterval(() => this.updateTimer(), 1000);
    }

    stopTimer() {
        clearInterval(this.timerInterval);
    }

    updateStatusIcon(status) {
        this.elements.statusIcon.innerHTML = UI.icons[status] || '';
    }

    updateStageToComplete() {
        // The new shell shows progress through the breadcrumb + statusbar,
        // so the standalone stage indicator was dropped. Keep this method
        // as a no-op when the legacy elements aren't in the DOM.
        if (this.elements.stageLine) {
            this.elements.stageLine.classList.remove('bg-gray-800');
            this.elements.stageLine.classList.add('bg-green-500/15');
        }
        if (this.elements.analysisStage) {
            this.elements.analysisStage.innerHTML = `
                <div class="w-10 h-10 rounded-full bg-green-500/8 border border-green-500/35 flex items-center justify-center">
                    <svg class="w-5 h-5 text-green-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                    </svg>
                </div>
                <span class="text-gray-400">Analysis</span>`;
        }
    }

    async startAnalysis() {
        this.updateStatusIcon('running');
        this.elements.analysisStatus.textContent = 'Running analysis...';
        this.startTimer();

        try {
            // Retrieve the arguments from localStorage
            const savedArgs = localStorage.getItem('analysisArgs');
            const args = savedArgs ? JSON.parse(savedArgs) : []; // Default to an empty array if no args are saved

            // POST to the same path the page was loaded from. This naturally
            // handles the EDR case (/analyze/edr/<profile>/<hash>) without
            // a special branch.
            const response = await fetch(window.location.pathname, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    args // Dynamically include the arguments retrieved from storage
                })
            });

            const data = await response.json();

            // Handle early termination
            if (data.status === 'early_termination') {
                this.updateTimer();
                this.stopTimer();
                this.updateStatusIcon('error');
                this.elements.analysisStatus.textContent = data.error || 'Process terminated early';
                
                // Create a minimal results object for summary
                const results = {
                    status: 'early_termination',
                    analysis_metadata: {
                        early_termination: true,
                        total_duration: data.details?.termination_time || 0
                    }
                };
                
                if (tools.summary) {
                    tools.summary.render(results);
                }
                return;
            }
            
            // Normal completion flow.
            //
            // Special-case EDR runs that are still in their Phase-2 alert
            // polling window: the page isn't actually done yet, so leave
            // the duration timer running and don't flip the status to
            // "Analysis completed". The EDR poll handler will stop the
            // timer + flip status when Phase 2 lands a terminal result.
            const edrPolling = !!(data.results && data.results.edr &&
                data.results.edr.status === 'polling_alerts');

            this.updateTimer();
            if (!edrPolling) {
                this.stopTimer();
                this.updateStatusIcon('complete');
                this.elements.analysisStatus.textContent = 'Analysis completed';
                this.updateStageToComplete();
            }

            // First update the summary with all results
            if (tools.summary && data.results) {
                try {
                    tools.summary.render(data.results);
                } catch (err) {
                    console.error('[results] summary render failed:', err);
                }
            }

            // Then process individual tool results — isolate each so a
            // single broken renderer doesn't suppress the rest.
            Object.entries(data.results || {}).forEach(([toolKey, results]) => {
                if (results && tools[toolKey] && toolKey !== 'summary') {
                    try {
                        tools[toolKey].render(results);
                    } catch (err) {
                        console.error(`[results] ${toolKey} render failed:`, err);
                    }
                }
            });
        } catch (error) {
            this.stopTimer();
            this.updateStatusIcon('error');
            this.elements.analysisStatus.textContent = `Error: ${error.message}`;
        }
    }

}

function handleUrlIdentifier() {
    const urlPath = window.location.pathname;
    const pathSegments = urlPath.split('/').filter(segment => segment.length > 0);
    const identifier = pathSegments[pathSegments.length - 1];

    if (isNumeric(identifier)) {
        const staticButton = document.getElementById('staticAnalysisButton');
        if (staticButton) {
            staticButton.style.display = 'none';
        }
    }

    function isNumeric(str) {
        return /^\d+$/.test(str);
    }
}

// HolyGrail scan function (add this anywhere in the file)
window.startHolyGrailScan = function() {
    const pathParts = window.location.pathname.split('/');
    const fileHash = pathParts[pathParts.length - 1];
    
    if (!fileHash) {
        console.error('No file hash found');
        return;
    }

    // Show loading message
    const button = document.getElementById('holygrailAnalysisButton');
    if (button) {
        button.innerHTML = `
            <svg class="w-5 h-5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>Starting HolyGrail Analysis...</span>
        `;
        button.disabled = true;
    }

    // Call HolyGrail analysis endpoint
    fetch(`/holygrail?hash=${fileHash}`, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            // Redirect to results page
            window.location.href = `/results/byovd/${fileHash}`;
        } else {
            // Handle error and restore button
            console.error('HolyGrail analysis failed:', data.error || data.message);
            restoreHolyGrailButton();
        }
    })
    .catch(error => {
        console.error('HolyGrail analysis error:', error);
        restoreHolyGrailButton();
    });

    function restoreHolyGrailButton() {
        if (button) {
            button.innerHTML = `
                <svg class="w-5 h-5 text-yellow-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 9v2a5 5 0 0010 0V9"/>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M6 9h12"/>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 16v3"/>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 19h6"/>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M6 9h-1a1 1 0 000 2h1M18 9h1a1 1 0 010 2h-1"/>
                </svg>
                <span>HolyGrail BYOVD Scan</span>
            `;
            button.disabled = false;
        }
    }
};

// Initialize Everything
document.addEventListener('DOMContentLoaded', function () {
    // Initialize tab navigation
    const tabManager = new TabManager();

    // Process URL identifier logic
    handleUrlIdentifier();

    // Initialize modal and analysis handlers
    const modal = new ModalHandler();
    const analysis = new AnalysisCore();
    // Expose so EDR's Phase-2 poll handler can stop the timer + flip the
    // status when correlation finishes — the duration chip should keep
    // ticking through Phase 2, not freeze when Phase 1 returns.
    window.__analysisCore = analysis;

    // Initialize PayloadManager
    const payloadManager = new PayloadManager();
    // Check file extension and show appropriate button
    const fileExtension = localStorage.getItem('currentFileExtension');
    const dynamicButton = document.getElementById('dynamicAnalysisButton');
    const holygrailButton = document.getElementById('holygrailAnalysisButton');
    
    if (fileExtension && fileExtension.toLowerCase() === 'sys') {
        // Show HolyGrail button for .sys files
        if (dynamicButton) dynamicButton.style.display = 'none';
        if (holygrailButton) holygrailButton.style.display = 'flex';
    } else {
        // Show Dynamic Analysis button for other files
        if (holygrailButton) holygrailButton.style.display = 'none';
        if (dynamicButton) dynamicButton.style.display = 'flex';
    }
    // Make modal functions globally accessible
    window.showDynamicWarning = () => {
        // Pre-populate the args input with whatever was last used so the user
        // can re-run with the same args or tweak them.
        const argsInput = document.getElementById('dynamicAnalysisArgs');
        if (argsInput) {
            try {
                const saved = JSON.parse(localStorage.getItem('analysisArgs') || '[]');
                argsInput.value = Array.isArray(saved) ? saved.join(' ') : '';
            } catch {
                argsInput.value = '';
            }
        }
        modal.show();
    };
    window.hideDynamicWarning = () => modal.hide();
    window.proceedWithDynamicAnalysis = (fileHash) => {
        const argsInput = document.getElementById('dynamicAnalysisArgs');
        const argsValue = argsInput ? argsInput.value : '';
        const args = argsValue.split(' ').filter(arg => arg.trim() !== '');
        localStorage.setItem('analysisArgs', JSON.stringify(args));
        window.location.href = `/analyze/dynamic/${fileHash}`;
    };

    // Start analysis if parameters exist
    if (analysis.analysisType && analysis.fileHash) {
        analysis.startAnalysis();
    }

    // Use PayloadManager methods
    window.updatePayloadOutput = (results) => payloadManager.updatePayloadOutput(results);
});

