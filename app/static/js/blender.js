// app/static/js/blender.js

class BlenderAnalyzer {
    constructor() {
        // Only initialize if we're in blender mode
        if (window.analysisType !== 'blender') return;
        
        this.bindElements();
        this.bindEvents();
        this.initialize();
    }

    bindElements() {
        // Updated element IDs to match new template
        this.scanButton = document.getElementById('startScan');
        this.resultsDiv = document.getElementById('blenderScanResults');
        this.resultsTitle = document.getElementById('blenderResultsTitle');
        this.scanActions = document.getElementById('scanActions');
        this.lastScanElement = document.getElementById('blenderLastScanTime');
        this.blenderContent = document.getElementById('blenderContent');
    }

    bindEvents() {
        if (!this.blenderContent) return; // Exit if not in blender view
        
        this.scanButton?.addEventListener('click', () => this.startSystemScan());
        
        // Set initial view on DOM content loaded
        document.addEventListener('DOMContentLoaded', () => {
            // Force scan view to be active by default
            this.switchView('scan');
            
            // Initialize view based on scan data
            if (window.initialScanData) {
                this.updateResults({ processes: window.initialScanData });
            }
        });
    }

    initialize() {
        if (!this.blenderContent) return; // Exit if not in blender view
        
        // Make scan view active by default
        this.switchView('scan');
        
        // Handle initial scan data
        if (!window.initialScanData) {
            this.showError('No system scan data available. Please run a system scan.');
            return;
        }

        // Update results with initial scan data
        this.updateResults({ processes: window.initialScanData });
        
        // Update last scan time if available
        if (window.lastScanDate) {
            this.updateLastScanTime(window.lastScanDate);
        }
    }

    switchView(view) {
        if (!this.blenderContent) return; // Exit if not in blender view
        
        // Update tab classes
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.remove('text-red-400', 'border-red-400', 'active');
            tab.classList.add('text-gray-400', 'border-transparent');
        });

        // Set active tab
        const activeTab = document.getElementById(`${view}View`);
        if (activeTab) {
            activeTab.classList.add('text-red-400', 'border-red-400', 'active');
            activeTab.classList.remove('text-gray-400', 'border-transparent');
        }

        if (view === 'scan') {
            this.scanActions?.classList.remove('hidden');
            if (this.resultsDiv) this.resultsDiv.innerHTML = '';
            if (this.resultsTitle) this.resultsTitle.textContent = 'System Scan Results';

            if (!window.initialScanData) {
                this.showError('No system scan data available. Please run a system scan.');
            } else {
                this.updateResults({ processes: window.initialScanData });
            }
        } else {
            this.scanActions?.classList.add('hidden');
            if (this.resultsTitle) this.resultsTitle.textContent = 'Payload Comparison';
            this.loadPayloadsForComparison();
        }
    }

    async startSystemScan() {
        if (!this.blenderContent || !this.scanButton) return;
        
        this.scanButton.disabled = true;
        this.scanButton.classList.add('opacity-50');
        this.showLoading('Creating new system scan...');

        try {
            const response = await fetch('/doppelganger', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    type: 'blender',
                    operation: 'scan' 
                })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.updateResults(data);
                const currentTime = new Date().toISOString();
                window.lastScanDate = currentTime;
                this.updateLastScanTime(currentTime);
            } else {
                this.showError(data.error || 'Operation failed');
            }
        } catch (error) {
            console.error('Error:', error);
            this.showError('Failed to start system scan');
        } finally {
            if (this.scanButton) {
                this.scanButton.disabled = false;
                this.scanButton.classList.remove('opacity-50');
            }
        }
    }

    // Fix for the updateResults method
    updateResults(data) {
        if (!this.resultsDiv) return;

        // Check if data exists
        if (!data) {
            this.showError('No data received from the system scan');
            return;
        }

        // Parse processes if they're in string format
        const processes = typeof data.processes === 'string' 
            ? JSON.parse(data.processes) 
            : data.processes;

        // Check if processes exist and are valid
        if (!processes) {
            this.showError('No system scan data available. Please run a system scan.');
            return;
        }

        // Check if processes array is empty
        if (processes.length === 0) {
            this.resultsDiv.innerHTML = `
                <div class="text-center text-gray-400">
                    <p>No issues detected in system scan</p>
                </div>
            `;
            return;
        }

        // Sort and display valid process results
        processes.sort((a, b) => b.iocs.length - a.iocs.length);
        this.displayProcessResults(processes);
    }

    displayProcessResults(processes) {
        let resultsHTML = this.generateProcessTableHeader();
        resultsHTML += this.generateProcessTableBody(processes);
        this.resultsDiv.innerHTML = resultsHTML;
    }

    generateProcessTableHeader() {
        return `
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-700">
                    <thead>
                        <tr>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">
                                Process Name
                            </th>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">
                                PID
                            </th>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">
                                Findings Count
                            </th>
                        </tr>
                    </thead>
                    <tbody class="bg-gray-900 divide-y divide-gray-700">
        `;
    }

    generateProcessTableBody(processes) {
        const rows = processes.map((process, index) => {
            const rowClass = index % 2 === 0 ? 'bg-gray-900' : 'bg-gray-800/50';
            const rowId = `process-${process.pid}`;
            
            return `
                <tr class="${rowClass} hover:bg-gray-700/50 transition-colors cursor-pointer" 
                    onclick="blenderAnalyzer.toggleProcessDetails('${rowId}')" 
                    data-pid="${process.pid}">
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-200">
                        <div class="flex items-center gap-2">
                            <svg class="w-4 h-4 transform transition-transform" id="arrow-${rowId}" 
                                 fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                      d="M9 5l7 7-7 7"/>
                            </svg>
                            ${process.process_name}
                        </div>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                        ${process.pid}
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                        ${process.iocs.length} findings
                    </td>
                </tr>
                <tr id="${rowId}" class="hidden">
                    <td colspan="3" class="px-6 py-4 bg-gray-800/30">
                        <div class="space-y-2">
                            ${process.iocs.map(ioc => this.formatIoc(ioc)).join('')}
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        return rows + `
                </tbody>
            </table>
        </div>
        `;
    }

    toggleProcessDetails(rowId) {
        const detailsRow = document.getElementById(rowId);
        const arrow = document.getElementById(`arrow-${rowId}`);
        
        if (detailsRow.classList.contains('hidden')) {
            detailsRow.classList.remove('hidden');
            arrow.classList.add('rotate-90');
        } else {
            detailsRow.classList.add('hidden');
            arrow.classList.remove('rotate-90');
        }
    }

    formatIoc(ioc) {
        if (ioc.type === 'HSB Detection' || (ioc.severity && !['HIGH', 'MEDIUM'].includes(ioc.severity))) {
            return this.formatHSBIoc(ioc);
        }
        if (ioc.severity && ['HIGH', 'MEDIUM'].includes(ioc.severity)) {
            return this.formatHollowsHunterIoc(ioc);
        }
        
        const parts = ioc.description.split('|').map(p => p.trim());
        return parts.length >= 2 ? this.formatMonetaIocWithAddress(ioc, parts) : this.formatSimpleIoc(ioc);
    }

    formatHSBIoc(ioc) {
        return `
            <div class="border-l-2 border-yellow-300 pl-4 py-2">
                <div class="flex flex-col gap-1">
                    <div class="flex items-center gap-2">
                        <span class="text-yellow-300 font-medium">${ioc.type}</span>
                        ${ioc.severity ? `<span class="text-xs text-gray-500">[${ioc.severity}]</span>` : ''}
                    </div>
                    <div class="text-gray-400 text-sm">
                        ${ioc.description}
                    </div>
                    ${ioc.thread_info ? `
                        <div class="text-gray-500 text-xs">
                            ${ioc.thread_info}
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    formatHollowsHunterIoc(ioc) {
        return `
            <div class="border-l-2 border-blue-300 pl-4 py-2">
                <div class="flex flex-col gap-1">
                    <div class="flex items-center gap-2">
                        <span class="text-blue-300 font-medium">${ioc.type}</span>
                        <span class="text-xs text-gray-500">[${ioc.severity}]</span>
                    </div>
                    <div class="text-gray-400 text-sm">
                        ${ioc.description}
                    </div>
                </div>
            </div>
        `;
    }

    formatMonetaIocWithAddress(ioc, parts) {
        const addrInfo = parts[0].split(':').map(p => p.trim());
        const [address, size] = addrInfo;
        
        return `
            <div class="border-l-2 border-pink-300 pl-4 py-2">
                <div class="flex flex-col gap-1">
                    <div class="flex items-center gap-2">
                        <span class="text-pink-300 font-medium">${ioc.type}</span>
                    </div>
                    <div class="grid grid-cols-2 gap-4 text-sm">
                        <div class="text-gray-400">
                            <span class="text-gray-500">Address:</span> ${address}
                        </div>
                        <div class="text-gray-400">
                            <span class="text-gray-500">Size:</span> ${size}
                        </div>
                    </div>
                    ${parts.slice(1).map(part => `
                        <div class="text-gray-400 text-sm">
                            ${part}
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    formatSimpleIoc(ioc) {
        return `
            <div class="border-l-2 border-pink-300 pl-4 py-2">
                <div class="flex flex-col gap-1">
                    <div class="flex items-center gap-2">
                        <span class="text-pink-300 font-medium">${ioc.type}</span>
                    </div>
                    <div class="text-gray-400 text-sm">
                        ${ioc.description}
                    </div>
                </div>
            </div>
        `;
    }

    async loadPayloadsForComparison() {
        this.showLoading('Loading available payloads...');

        try {
            const response = await fetch('/files');
            const data = await response.json();
            
            if (data.status === 'success') {
                this.displayPayloads(data.payload_based.payloads);
            }
        } catch (error) {
            console.error('Error:', error);
            this.showError('Failed to load payloads');
        }
    }

    // New helper method to check if files object is empty
    displayPayloads(files) {
        if (!files || Object.keys(files).length === 0) {
            this.resultsDiv.innerHTML = `
                <div class="flex flex-col items-center justify-center py-12 px-4 bg-gray-800/20 rounded-lg">
                    <div class="mb-6">
                        <svg class="w-16 h-16 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" 
                                d="M4 5a2 2 0 012-2h4.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V19a2 2 0 01-2 2H6a2 2 0 01-2-2V5z"/>
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" 
                                d="M12 15v.01M12 12v-4"/>
                        </svg>
                    </div>
                    
                    <h3 class="text-xl font-medium text-gray-300 mb-3">
                        No Payloads Available
                    </h3>
                    
                    <div class="space-y-2 text-center max-w-md">
                        <p class="text-gray-400">
                            There are currently no payloads available for analysis in the system.
                        </p>
                        <p class="text-gray-500 text-sm">
                            Upload payloads through the interface to begin the analysis process.
                        </p>
                    </div>

                    <div class="mt-6 flex gap-4">
                        <a href="/" class="px-4 py-2 bg-pink-500/10 text-green-400 rounded-lg border border-green-500/20 hover:bg-green-500/20 transition-colors">
                            Upload Payloads
                        </a>
                    </div>
                </div>
            `;
            return;
        }

        this.resultsDiv.innerHTML = `
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-700">
                    <thead>
                        <tr>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">File name</th>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">Risk factors</th>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">Upload date</th>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">Action</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-800">
                        ${Object.entries(files).map(([id, file], index) => this.generatePayloadRow(file, index)).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    generatePayloadRow(file, index) {
        const hasSystemScan = window.initialScanData !== undefined && window.initialScanData !== null;
        
        return `
            <tr class="${index % 2 === 0 ? 'bg-gray-900/30' : 'bg-gray-800/30'}">
                <td class="px-6 py-4">
                    <div class="flex flex-col">
                        <span class="text-gray-200">${file.filename}</span>
                        <span class="text-sm text-gray-500 font-mono">${file.md5}</span>
                    </div>
                </td>
                <td class="px-6 py-4 text-sm text-gray-400">
                    <div class="space-y-1">
                        ${file.risk_assessment.factors.map(factor => `
                            <div class="flex items-center gap-2">
                                <svg class="w-3 h-3 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                                </svg>
                                <span>${factor}</span>
                            </div>
                        `).join('')}
                    </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">${file.upload_time}</td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <button 
                        ${hasSystemScan ? `onclick="blenderAnalyzer.compareWithPayload('${file.md5}')"` : 'disabled'} 
                        class="px-3 py-1 ${hasSystemScan ? 'text-red-400 border-red-900/20 hover:bg-red-500/10 cursor-pointer' : 'text-gray-500 border-gray-700 opacity-50 cursor-not-allowed'} border rounded-lg transition-colors"
                        ${!hasSystemScan ? 'title="Please run a system scan first"' : ''}>
                        Compare
                    </button>
                </td>
            </tr>
        `;
    }

    async compareWithPayload(hash) {
        if (!this.blenderContent) return;
        
        this.showLoading('Comparing with payload...');
        try {
            const response = await fetch(`/doppelganger?type=blender&hash=${encodeURIComponent(hash)}`, {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' }
            });
            
            const data = await response.json();
            
            if (data.error) {
                this.showError(data.error);
                return;
            }
            
            if (data.status === 'success' && data.result.matches?.length > 0) {
                this.displayComparisonResults(data, hash);
            } else {
                this.showError('No matching processes found above 50% confidence');
            }
        } catch (error) {
            console.error('Error:', error);
            this.showError('Failed to compare with payload');
        }
    }

    displayComparisonResults(data, hash) {
        const matches = data.result.matches[0].matches
            .filter(match => match.match_percentage >= 50)
            .sort((a, b) => b.match_percentage - a.match_percentage)

        const payloadIOCs = data.result.payload_processes[0].iocs;

        this.resultsDiv.innerHTML = `
            <div class="space-y-6">
                <div class="bg-gray-800/50 p-4 rounded-lg">
                    <h3 class="text-lg font-medium text-gray-200">Payload Analysis</h3>
                    <div class="text-sm text-gray-400 mb-4">Hash: ${hash}</div>
                    ${this.formatPayloadIOCs(payloadIOCs)}
                </div>

                <div class="bg-gray-800/50 p-4 rounded-lg">
                    <h3 class="text-lg font-medium text-gray-200">${matches.length} Matching Processes</h3>
                    <div class="space-y-4 mt-4">
                        ${matches.map(match => this.formatMatchResult(match, payloadIOCs)).join('')}
                    </div>
                </div>
            </div>
        `;
    }

    formatMatchResult(match, payloadIOCs) {
        return `
            <div class="border border-gray-700 rounded-lg p-4">
                <div class="flex items-center justify-between mb-4">
                    <div class="flex items-center gap-4">
                        <span class="text-2xl font-bold ${this.getMatchPercentageColor(match.match_percentage)}">
                            ${match.match_percentage}%
                        </span>
                        <div>
                            <h4 class="text-lg font-medium text-gray-200">${match.process_name}</h4>
                            <div class="text-sm text-gray-400">PID: ${match.pid}</div>
                        </div>
                    </div>
                </div>
                ${this.formatMatchedIOCs(match.matching_iocs, payloadIOCs)}
            </div>
        `;
    }

    getMatchPercentageColor(percentage) {
        if (percentage >= 90) return 'text-green-400';
        if (percentage >= 70) return 'text-yellow-400';
        return 'text-blue-400';
    }

    formatPayloadIOCs(iocs) {
        const groupedIOCs = this.groupIOCsByCategory(iocs);

        return `
            <div class="border-l-4 border-purple-500 pl-4">
                <div class="text-lg text-purple-400 mb-2">Original Payload IOCs</div>
                ${Object.entries(groupedIOCs).map(([category, categoryIOCs]) => this.formatIOCCategory(category, categoryIOCs)).join('')}
            </div>
        `;
    }

    formatIOCCategory(category, iocs) {
        return `
            <div class="mb-4">
                <h4 class="text-sm font-medium text-gray-300 mb-2">${category}</h4>
                <div class="space-y-2">
                    ${iocs.map(ioc => this.formatCategoryIOC(ioc)).join('')}
                </div>
            </div>
        `;
    }

    formatCategoryIOC(ioc) {
        return `
            <div class="bg-gray-800/30 rounded p-3">
                <div class="flex items-center gap-2 mb-1">
                    <span class="text-sm font-medium ${this.getIOCSeverityColor(ioc.severity)}">
                        ${ioc.type}
                    </span>
                    ${ioc.severity ? 
                        `<span class="text-xs px-2 py-0.5 rounded-full bg-gray-700/50 text-gray-400">
                            ${ioc.severity}
                        </span>` 
                        : ''
                    }
                </div>
                <div class="text-sm text-gray-400 mt-1">
                    ${this.formatIOCDescription(ioc)}
                </div>
            </div>
        `;
    }

    formatMatchedIOCs(matchingIOCs, payloadIOCs) {
        const groupedMatchingIOCs = this.groupIOCsByCategory(matchingIOCs);
        const groupedPayloadIOCs = this.groupIOCsByCategory(payloadIOCs);
        const allCategories = new Set([...Object.keys(groupedMatchingIOCs), ...Object.keys(groupedPayloadIOCs)]);

        let html = '';
        allCategories.forEach(category => {
            const matchingCategoryIOCs = groupedMatchingIOCs[category] || [];
            const payloadCategoryIOCs = groupedPayloadIOCs[category] || [];

            html += this.formatMatchedIOCCategory(category, matchingCategoryIOCs, payloadCategoryIOCs);
        });
        return html;
    }

    formatMatchedIOCCategory(category, matchingIOCs, payloadIOCs) {
        return `
            <div class="mb-6">
                <h4 class="text-sm font-medium text-gray-300 mb-2">${category}</h4>
                <div class="grid grid-cols-2 gap-4">
                    ${this.formatIOCComparison(matchingIOCs, payloadIOCs)}
                </div>
            </div>
        `;
    }

    formatIOCComparison(matchingIOCs, payloadIOCs) {
        return `
            <div class="bg-blue-900/20 rounded-lg p-4">
                <div class="text-sm font-medium text-pink-400 mb-2">Process IOCs</div>
                <div class="space-y-2">
                    ${matchingIOCs.map(ioc => this.formatMatchingIOC(ioc)).join('')}
                </div>
            </div>
            <div class="bg-purple-900/20 rounded-lg p-4">
                <div class="text-sm font-medium text-purple-400 mb-2">Payload IOCs</div>
                <div class="space-y-2">
                    ${payloadIOCs.map(ioc => this.formatPayloadIOC(ioc)).join('')}
                </div>
            </div>
        `;
    }


    formatMatchingIOC(ioc) {
        return `
            <div class="bg-gray-800/30 rounded p-3">
                <div class="flex items-center gap-2 mb-1">
                    <span class="text-sm font-medium ${this.getIOCSeverityColor(ioc.severity)}">${ioc.type}</span>
                    ${ioc.severity ? 
                        `<span class="text-xs px-2 py-0.5 rounded-full bg-gray-700/50 text-gray-400">
                            ${ioc.severity}
                        </span>` 
                        : ''
                    }
                </div>
                ${ioc.match_score < 1 ? 
                    `<div class="text-xs text-amber-400/70 mb-1">
                        Match confidence: ${Math.round(ioc.match_score * 100)}%
                    </div>` 
                    : ''
                }
                <div class="text-sm text-gray-400 mt-1">
                    ${this.formatIOCDescription(ioc)}
                </div>
            </div>
        `;
    }

    formatPayloadIOC(ioc) {
        return `
            <div class="bg-gray-800/30 rounded p-3">
                <div class="flex items-center gap-2 mb-1">
                    <span class="text-sm font-medium ${this.getIOCSeverityColor(ioc.severity)}">${ioc.type}</span>
                    ${ioc.severity ? 
                        `<span class="text-xs px-2 py-0.5 rounded-full bg-gray-700/50 text-gray-400">
                            ${ioc.severity}
                        </span>` 
                        : ''
                    }
                </div>
                <div class="text-sm text-gray-400 mt-1">
                    ${this.formatIOCDescription(ioc)}
                </div>
            </div>
        `;
    }

    getIOCSeverityColor(severity) {
        switch(severity) {
            case 'HIGH': return 'text-red-400';
            case 'MEDIUM':
            case 'MID': return 'text-yellow-400';
            default: return 'text-blue-400';
        }
    }

    formatIOCDescription(ioc) {
        const cleanDescription = ioc.system_description || ioc.description;
        let formattedDesc = cleanDescription.replace(/0x[0-9a-fA-F]+/g, '[addr]');
        
        return formattedDesc.replace(/([A-Z]:\\[^|]+\\)([^|]+)(\s*\||$)/g, (match, path, filename) => {
            return path.length > 30 ? `...\\${filename}${match.endsWith('|') ? ' |' : ''}` : match;
        });
    }

    groupIOCsByCategory(iocs) {
        return iocs.reduce((acc, ioc) => {
            const category = ioc.dll || 'Process Level';
            if (!acc[category]) {
                acc[category] = [];
            }
            acc[category].push(ioc);
            return acc;
        }, {});
    }

    showLoading(message) {
        if (!this.resultsDiv) return;
        
        this.resultsDiv.innerHTML = `
            <div class="flex items-center justify-center text-gray-400">
                <svg class="animate-spin h-5 w-5 mr-3" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <span>${message}</span>
            </div>
        `;
    }

    showError(message) {
        if (!this.resultsDiv) return;
        
        this.resultsDiv.innerHTML = `
            <div class="flex items-center justify-center text-red-400">
                <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <span>${message}</span>
            </div>
        `;
    }

    updateLastScanTime(timestamp = null) {
        if (!this.lastScanElement) return;

        const date = timestamp ? new Date(timestamp) : new Date();
        const formattedDate = this.formatDateTime(date);
        
        this.lastScanElement.innerHTML = `
            <div class="flex items-center gap-2">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                        d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <span>Last scan: ${formattedDate}</span>
            </div>
        `;
    }

    formatDateTime(date) {
        const pad = (num) => String(num).padStart(2, '0');
        
        const year = date.getFullYear();
        const month = pad(date.getMonth() + 1);
        const day = pad(date.getDate());
        const hours = pad(date.getHours());
        const minutes = pad(date.getMinutes());
        const seconds = pad(date.getSeconds());
        
        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    }
}


// Export for global access
if (window.analysisType === 'blender') {
    window.blenderAnalyzer = new BlenderAnalyzer();
}