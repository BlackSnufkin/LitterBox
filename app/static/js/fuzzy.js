// app/static/js/fuzzy.js

class FuzzyAnalyzer {
    constructor() {
        // Only initialize if we're in fuzzy mode
        if (window.analysisType !== 'fuzzy') return;

        // Initialize state
        this.currentView = null;
        
        // Initialize components
        this.bindElements();
        this.bindEvents();
        this.initialize();
    }

    // DOM Element Bindings
    bindElements() {
        // Core elements
        this.elements = {
            fuzzyContent: document.getElementById('fuzzyContent'),
            results: document.getElementById('fuzzyAnalysisResults'),
            resultsTitle: document.getElementById('fuzzyResultsTitle'),
            createDbForm: document.getElementById('createDbForm'),
            analyzeForm: document.getElementById('analyzeForm'),
            dbStats: document.getElementById('databaseStats'),
            folderPath: document.getElementById('folderPath'),
            tabs: {
                createDb: document.getElementById('createDbView'),
                analyze: document.getElementById('analyzeView')
            }
        };

        // Exit if not in fuzzy view
        if (!this.elements.fuzzyContent) return;
    }


    // Event Bindings
    bindEvents() {
        if (!this.elements.fuzzyContent) return;

        // DOM Ready event
        document.addEventListener('DOMContentLoaded', () => this.handleDOMReady());

        // Input events
        this.elements.folderPath?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.createDb();
        });
    }

    handleDOMReady() {
        if (!this.elements.fuzzyContent) return;

        const currentView = document.querySelector('.nav-tab.active')?.id.replace('View', '');
        if (currentView === 'analyze') {
            this.loadAvailableFiles();
        }
    }

    // Initialization
    initialize() {
        if (!this.elements.fuzzyContent) return;

        this.currentView = document.querySelector('.nav-tab.active')?.id.replace('View', '') || 'create_db';
        if (this.currentView === 'analyze') {
            this.loadAvailableFiles();
        }
        this.loadDatabaseStats();
    }

    // View Management
    switchView(view) {
        if (!this.elements.fuzzyContent) return;

        // Update tab states
        this.updateTabStates(view);
        
        // Update form visibility
        this.updateFormVisibility(view);
        
        // Update content
        this.updateContent(view);
        
        // Store current view
        this.currentView = view;
    }

    updateTabStates(view) {
        if (!this.elements.tabs) return;

        // Reset all tabs
        const inactiveClasses = 'nav-tab px-4 py-2 -mb-px border-b-2 text-gray-400 border-transparent';
        const activeClasses = 'nav-tab px-4 py-2 -mb-px border-b-2 active border-blue-500 text-blue-500';

        Object.values(this.elements.tabs).forEach(tab => {
            if (tab) tab.className = inactiveClasses;
        });

        // Set active tab
        const activeTab = this.elements.tabs[view === 'create_db' ? 'createDb' : 'analyze'];
        if (activeTab) {
            activeTab.className = activeClasses;
        }
    }

    updateFormVisibility(view) {
        if (!this.elements.createDbForm || !this.elements.analyzeForm) return;

        this.elements.createDbForm.classList.toggle('hidden', view !== 'create_db');
        this.elements.analyzeForm.classList.toggle('hidden', view !== 'analyze');
    }

    updateContent(view) {
        if (!this.elements.resultsTitle || !this.elements.results) return;

        // Update title
        const titles = {
            'create_db': 'Database Creation Results',
            'analyze': 'Available Files for Analysis'
        };
        this.elements.resultsTitle.textContent = titles[view] || 'Results';

        // Load appropriate content
        if (view === 'analyze') {
            this.loadAvailableFiles();
        } else {
            this.clearResults();
        }
    }


    updateFormVisibility(view) {
        this.elements.createDbForm.classList.toggle('hidden', view !== 'create_db');
        this.elements.analyzeForm.classList.toggle('hidden', view !== 'analyze');
    }

    updateContent(view) {
        // Update title
        const titles = {
            'create_db': 'Database Creation Results',
            'analyze': 'Available Files for Analysis'
        };
        this.elements.resultsTitle.textContent = titles[view] || 'Results';

        // Load appropriate content
        if (view === 'analyze') {
            this.loadAvailableFiles();
        } else {
            this.clearResults();
        }
    }

    // Database Statistics
    loadDatabaseStats() {
        if (!this.elements.dbStats) return;

        if (!this.validateDatabaseStats()) {
            this.showDatabaseError();
            return;
        }
        this.renderDatabaseStats();
    }

    validateDatabaseStats() {
        return window.dbStats && window.dbStats.total_files !== 0;
    }

    showDatabaseError() {
        if (!this.elements.dbStats) return;
        this.elements.dbStats.innerHTML = this.templates.databaseError();
    }

    renderDatabaseStats() {
        if (!this.elements.dbStats) return;
        this.elements.dbStats.innerHTML = this.templates.databaseStats(window.dbStats);
    }

    // File Analysis Operations
    async loadAvailableFiles() {
        if (!this.elements.results) return;

        this.showLoading('Loading available files...');

        try {
            const response = await this.api.getFiles();
            
            if (response.status === 'success') {
                this.displayAvailableFiles(response.payload_based.payloads);
            } else {
                this.showError('Failed to load files');
            }
        } catch (error) {
            console.error('Error:', error);
            this.showError('Failed to load available files');
        }
    }

    displayAvailableFiles(files) {
        if (!this.elements.results) return;

        if (!files || Object.keys(files).length === 0) {
            this.elements.results.innerHTML = this.templates.noFiles();
            return;
        }

        this.elements.results.innerHTML = this.templates.filesList(files);
    }

    async analyzeFile(hash) {
        if (!this.elements.results) return;

        this.showLoading('Analyzing file...');

        try {
            const response = await this.api.analyzeFile(hash);
            this.displayResults(this.templates.analysisResults(response));
        } catch (error) {
            console.error('Analysis error:', error);
            this.showError(error.message);
        }
    }

    // Database Operations
    async createDb() {
        if (!this.elements.folderPath || !this.elements.results) return;

        const folderPath = this.elements.folderPath.value.trim();
        
        if (!folderPath) {
            this.showError('Folder path is required');
            return;
        }

        this.showLoading('Creating database...');

        try {
            const response = await this.api.createDatabase(folderPath);
            
            if (response.status === 'success') {
                // Update the global dbStats with the new stats
                window.dbStats = {
                    total_files: response.stats.processed,
                    db_size_human: 'Updated',
                    last_updated: new Date().toLocaleString(),
                    total_size_human: 'Calculating...',
                    sources: response.stats.sources.reduce((acc, src) => {
                        acc[src] = { count: 1 };
                        return acc;
                    }, {})
                };

                // Display creation results
                this.displayResults(this.templates.databaseResults(response));
                
                // Clear any error message in the stats section
                if (this.elements.dbStats) {
                    this.elements.dbStats.innerHTML = this.templates.databaseStats(window.dbStats);
                }
                
                // Optionally, fetch fresh stats
                try {
                    const statsResponse = await this.api.getDatabaseStats();
                    if (statsResponse.status === 'success') {
                        window.dbStats = statsResponse.stats;
                        if (this.elements.dbStats) {
                            this.elements.dbStats.innerHTML = this.templates.databaseStats(window.dbStats);
                        }
                    }
                } catch (statsError) {
                    console.error('Error fetching updated stats:', statsError);
                }
            } else {
                this.showError(response.error || 'Failed to create database');
            }
        } catch (error) {
            console.error('Create DB error:', error);
            this.showError(error.message || 'Failed to create database');
        }
    }

    // UI Helpers
    showLoading(message = 'Processing...') {
        if (!this.elements.results) return;
        this.elements.results.innerHTML = this.templates.loading(message);
    }

    showError(message) {
        if (!this.elements.results) return;
        this.elements.results.innerHTML = this.templates.error(message);
    }

    clearResults() {
        if (!this.elements.results) return;
        this.elements.results.innerHTML = '';
    }

    displayResults(html) {
        if (!this.elements.results) return;
        this.elements.results.innerHTML = html;
    }

    // Utility Methods
    formatHexView(data) {
        if (!data || !data.length) return 'No printable characters found';
        
        const lines = data.map(block => {
            return block.ascii_repr.split('\n')
                .filter(line => !line.split('').every(char => char === '.'))
                .map(line => line.trim())
                .filter(Boolean);
        }).flat();
        
        return lines.length ? lines.join('\n') : 'No printable characters found';
    }

    getSimilarityColor(similarity) {
        if (similarity >= 90) return 'text-green-400';
        if (similarity >= 70) return 'text-yellow-400';
        if (similarity >= 50) return 'text-blue-400';
        return 'text-gray-400';
    }

    // API Methods
    api = {
        createDatabase: async (folderPath, extensions) => {
            return await fetch('/doppelganger', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    type: 'fuzzy',
                    operation: 'create_db',
                    folder_path: folderPath,
                    extensions: extensions
                })
            }).then(r => r.json());
        },

        getFiles: async () => {
            return await fetch('/files').then(r => r.json());
        },

        analyzeFile: async (hash) => {
            return await fetch('/doppelganger', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    type: 'fuzzy',
                    operation: 'analyze',
                    hash: hash,
                    threshold: 1
                })
            }).then(r => r.json());
        }
    };

    toggleSources(event) {
        const button = event.currentTarget;
        const sourcesList = button.parentElement.nextElementSibling;
        const expandIcon = button.querySelector('.expand-icon');
        const expandText = button.querySelector('.expand-text');
        
        if (sourcesList.style.maxHeight === '100px') {
            sourcesList.style.maxHeight = sourcesList.scrollHeight + 'px';
            expandIcon.classList.add('rotate-180');
            expandText.textContent = 'Show Less';
        } else {
            sourcesList.style.maxHeight = '100px';
            expandIcon.classList.remove('rotate-180');
            expandText.textContent = 'Show More';
        }
    }

    toggleRegionContent(event) {
        const regionContainer = event.currentTarget.closest('.p-4');
        const contentBlocks = regionContainer.querySelectorAll('.content-block');
        const expandIcon = event.currentTarget.querySelector('.expand-icon');
        const expandText = event.currentTarget.querySelector('.expand-text');
        
        if (contentBlocks[0].style.maxHeight === '100px') {
            contentBlocks.forEach(block => {
                block.style.maxHeight = block.scrollHeight + 'px';
            });
            expandIcon.classList.add('rotate-180');
            expandText.textContent = 'Show Less';
        } else {
            contentBlocks.forEach(block => {
                block.style.maxHeight = '100px';
            });
            expandIcon.classList.remove('rotate-180');
            expandText.textContent = 'Show More';
        }
    }
    // Templates
    templates = {
        loading: (message) => `
            <div class="flex items-center justify-center p-4">
                <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500"></div>
                <span class="ml-2 text-gray-400">${message}</span>
            </div>
        `,

        error: (message) => `
            <div class="bg-red-900/20 border border-red-900/50 text-red-400 px-4 py-3 rounded">
                Error: ${message}
            </div>
        `,

        databaseError: () => `
            <h2 class="text-lg font-medium text-gray-100 mb-4">Database Statistics</h2>
            <div class="bg-red-900/20 border border-red-900/50 text-red-400 px-4 py-3 rounded">
                Error: No database found. Create a database to get started.
            </div>
        `,

        databaseStats: (stats) => `
            <h2 class="text-lg font-medium text-gray-100 mb-4">Database Statistics</h2>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div class="bg-gray-700/50 rounded-lg p-4">
                    <h3 class="text-sm font-medium text-gray-300 mb-2">Database Info</h3>
                    <div class="space-y-2 text-sm">
                        <div>
                            <span class="text-gray-400">Database Size:</span>
                            <span class="text-gray-100 ml-2">${stats.db_size_human}</span>
                        </div>
                        <div>
                            <span class="text-gray-400">Last Updated:</span>
                            <span class="text-gray-100 ml-2">${stats.last_updated}</span>
                        </div>
                    </div>
                </div>
                <div class="bg-gray-700/50 rounded-lg p-4">
                    <h3 class="text-sm font-medium text-gray-300 mb-2">Content Info</h3>
                    <div class="space-y-2 text-sm">
                        <div>
                            <span class="text-gray-400">Total Files:</span>
                            <span class="text-gray-100 ml-2">${stats.total_files}</span>
                        </div>
                        <div>
                            <span class="text-gray-400">Total Files Size:</span>
                            <span class="text-gray-100 ml-2">${stats.total_size_human}</span>
                        </div>
                    </div>
                </div>
                <div class="bg-gray-700/50 rounded-lg p-4">
                    <div class="flex justify-between items-center mb-2">
                        <div class="flex items-center gap-2">
                            <h3 class="text-sm font-medium text-gray-300">Sources</h3>
                            <span class="text-xs text-gray-400">(${Object.keys(stats.sources).length} total)</span>
                        </div>
                        <button onclick="fuzzyAnalyzer.toggleSources(event)" 
                                class="text-blue-400 text-sm hover:text-blue-300 flex items-center gap-1">
                            <span class="expand-text">Show More</span>
                            <svg class="w-4 h-4 transform transition-transform expand-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                            </svg>
                        </button>
                    </div>
                    <div class="space-y-2 text-sm sources-list" style="max-height: 100px; overflow: hidden; transition: max-height 0.3s ease-in-out">
                        ${Object.entries(stats.sources).map(([source, data]) => `
                            <div>
                                <span class="text-yellow-400">${source}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `,
        noFiles: () => `
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
                    No Files Available
                </h3>
                
                <div class="space-y-2 text-center max-w-md">
                    <p class="text-gray-400">
                        There are currently no files available for analysis in the system.
                    </p>
                    <p class="text-gray-500 text-sm">
                        Upload files through the interface to begin the analysis process.
                    </p>
                </div>

                <div class="mt-6 flex gap-4">
                    <a href="/" class="px-4 py-2 bg-pink-500/10 text-green-400 rounded-lg border border-green-500/20 hover:bg-green-500/20 transition-colors">
                        Upload Files
                    </a>
                </div>
            </div>
        `,

        filesList: (files) => `
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-700">
                    <thead>
                        <tr>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">File name</th>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">Hash</th>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">Upload date</th>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">Action</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-800">
                        ${Object.entries(files).map(([id, file], index) => `
                            <tr class="${index % 2 === 0 ? 'bg-gray-900/30' : 'bg-gray-800/30'}">
                                <td class="px-6 py-4">
                                    <span class="text-gray-200">${file.filename}</span>
                                </td>
                                <td class="px-6 py-4">
                                    <span class="text-sm text-gray-500 font-mono">${file.md5}</span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                                    ${file.upload_time}
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <button onclick="fuzzyAnalyzer.analyzeFile('${file.md5}')"
                                            class="px-3 py-1 text-blue-400 border border-blue-900/20 rounded-lg hover:bg-blue-500/10 transition-colors">
                                        Compare
                                    </button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `,

        databaseResults: (data) => `
            <div class="space-y-4">
                <div class="p-4 bg-gray-700/50 rounded-lg">
                    <h3 class="text-lg font-medium text-gray-100 mb-2">Database Creation Complete</h3>
                    <div class="grid grid-cols-2 gap-4 text-sm">
                        <div>
                            <span class="text-gray-400">Processed Files:</span>
                            <span class="text-gray-100 ml-2">${data.stats.processed}</span>
                        </div>
                        <div>
                            <span class="text-gray-400">Skipped Files:</span>
                            <span class="text-gray-100 ml-2">${data.stats.skipped}</span>
                        </div>
                        <div>
                            <span class="text-gray-400">Total Files:</span>
                            <span class="text-gray-100 ml-2">${data.stats.total}</span>
                        </div>
                        <div>
                            <span class="text-gray-400">Sources:</span>
                            <span class="text-gray-100 ml-2">${data.stats.sources.join(', ') || 'None'}</span>
                        </div>
                    </div>
                </div>
            </div>
        `,

        analysisResults: (data) => {
            if (!data.results || !data.results.length) {
                return `
                    <div class="text-center text-gray-400 py-4">
                        <p>No matches found in the database</p>
                    </div>
                `;
            }

            return data.results.map(result => `
                <div class="p-4 bg-gray-700/50 rounded-lg mb-4">
                    <h3 class="text-lg font-medium text-gray-100 mb-2">Results for: ${result.file}</h3>
                    <div class="space-y-2 text-sm">
                        <div>
                            <span class="text-gray-400">MD5:</span>
                            <span class="text-gray-100 ml-2 font-mono">${result.md5}</span>
                        </div>
                        <div>
                            <span class="text-gray-400">File Size:</span>
                            <span class="text-gray-100 ml-2">${result.file_size} bytes</span>
                        </div>
                        <div>
                            <span class="text-gray-400">Total Blocks in File:</span>
                            <span class="text-gray-100 ml-2">${result.total_blocks}</span>
                        </div>
                        <div>
                            <span class="text-gray-400">Matches Found:</span>
                            <span class="text-gray-100 ml-2">${result.total_matches} files</span>
                        </div>
                    </div>
                    ${this.templates.matches(result.matches, result.total_blocks)}
                </div>
            `).join('');
        },

        matches: (matches, totalBlocks) => {
            if (!matches || !matches.length) return '';

            return `
                <div class="mt-4 space-y-4">
                    ${matches.map(match => `
                        <div class="bg-gray-800/50 rounded-lg overflow-hidden border border-gray-700">
                            <!-- Match Header -->
                            <div class="p-4 border-b border-gray-700">
                                <div class="flex justify-between items-start mb-2">
                                    <div>
                                        <div class="text-gray-100">${match.file}</div>
                                        <div class="text-sm text-gray-400">Source: ${match.source}</div>
                                    </div>
                                    <div class="text-right">
                                        <div class="text-2xl font-bold ${this.getSimilarityColor(match.overall_similarity)}">
                                            ${match.overall_similarity.toFixed(1)}%
                                        </div>
                                        <div class="text-sm text-gray-400">Similar</div>
                                    </div>
                                </div>
                                <div class="grid grid-cols-2 gap-4 text-sm">
                                    <div>
                                        <span class="text-gray-400">Target Size:</span>
                                        <span class="text-gray-100 ml-2">${match.target_size} bytes</span>
                                    </div>
                                    <div>
                                        <span class="text-gray-400">MD5:</span>
                                        <span class="text-gray-100 ml-2 font-mono">${match.md5}</span>
                                    </div>
                                    <div>
                                        <span class="text-gray-400">Added:</span>
                                        <span class="text-gray-100 ml-2">${match.date_added}</span>
                                    </div>
                                    <div>
                                        <span class="text-gray-400">Matching Regions:</span>
                                        <span class="text-gray-100 ml-2">${match.total_regions} out of ${totalBlocks}</span>
                                    </div>
                                </div>
                            </div>

                            <!-- Matching Regions -->
                            ${this.templates.matchingRegions(match.matching_regions)}
                        </div>
                    `).join('')}
                </div>
            `;
        },

        matchingRegions: (regions) => {
            return regions.map((region, index) => `
                <div class="p-4 border-t border-gray-700">
                    <!-- Region Header -->
                    <div class="mb-6">
                        <div class="flex justify-between items-center mb-2">
                            <h4 class="text-lg font-medium text-gray-100">Region ${index + 1}</h4>
                            <div class="text-sm flex items-center gap-4">
                                <span class="text-blue-400 font-medium">${region.avg_similarity.toFixed(1)}% Similar</span>
                                <span class="text-gray-400">(${region.length} bytes)</span>
                                <button onclick="fuzzyAnalyzer.toggleRegionContent(event)" 
                                        class="text-blue-400 text-sm hover:text-blue-300 flex items-center gap-1">
                                    <span class="expand-text">Show More</span>
                                    <svg class="w-4 h-4 transform transition-transform expand-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                                    </svg>
                                </button>
                            </div>
                        </div>
                        <!-- Memory Ranges -->
                        <div class="grid grid-cols-2 gap-4 text-sm bg-gray-800/50 p-3 rounded-lg">
                            <div>
                                <div class="text-gray-400">Memory Range in DB File:</div>
                                <div class="font-mono text-gray-100">
                                    ${region.target_start.toString(16).padStart(8, '0')} - ${(region.target_start + region.length).toString(16).padStart(8, '0')}
                                </div>
                            </div>
                            <div>
                                <div class="text-gray-400">Memory Range in Payload File:</div>
                                <div class="font-mono text-gray-100">
                                    ${region.source_start.toString(16).padStart(8, '0')} - ${(region.source_start + region.length).toString(16).padStart(8, '0')}
                                </div>
                            </div>
                        </div>
                    </div>
                    <!-- Data Comparison -->
                    <div class="grid grid-cols-2 gap-6">
                        <!-- Database File Data -->
                        <div class="space-y-2">
                            <div class="flex items-center bg-purple-900/20 text-purple-400 px-3 py-2 rounded-t-lg border-b border-purple-900/50">
                                <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                                </svg>
                                Database File Contents
                            </div>
                            <div class="overflow-x-auto bg-gray-900/50 rounded-b-lg p-3">
                                <pre class="font-mono text-xs leading-relaxed whitespace-pre text-gray-300 content-block" style="max-height: 100px; overflow: hidden; transition: max-height 0.3s ease-in-out">${this.formatHexView(region.target_data)}</pre>
                            </div>
                        </div>
                        <!-- Payload File Data -->
                        <div class="space-y-2">
                            <div class="flex items-center bg-blue-900/20 text-blue-400 px-3 py-2 rounded-t-lg border-b border-blue-900/50">
                                <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                                </svg>
                                Payload File Contents (Being Analyzed)
                            </div>
                            <div class="overflow-x-auto bg-gray-900/50 rounded-b-lg p-3">
                                <pre class="font-mono text-xs leading-relaxed whitespace-pre text-gray-300 content-block" style="max-height: 100px; overflow: hidden; transition: max-height 0.3s ease-in-out">${this.formatHexView(region.source_data)}</pre>
                            </div>
                        </div>
                    </div>
                </div>
            `).join('');
        }
    };
}

if (window.analysisType === 'fuzzy') {
    window.fuzzyAnalyzer = new FuzzyAnalyzer();
}