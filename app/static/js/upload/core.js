// app/static/js/upload/core.js
// DOMContentLoaded entry for the upload page (/).
// Drag-drop, validation, POST /upload, file metadata rendering,
// and analysis-button wiring.

import {
    createLnkInfoSection,
    renderLnkInfo,
    calculateLnkRisk,
    getRiskLevelClass,
    getTargetCommandBorderClass,
    getTargetCommandTextClass,
} from './lnk.js';

// app/static/js/upload_updated.js

// Check if serverConfig exists and use a default if it doesn't
const maxFileSize = (window.serverConfig && window.serverConfig.maxFileSize) || 100 * 1024 * 1024;
const maxFileSizeMB = (window.serverConfig && window.serverConfig.maxFileSizeMB) || 100;

// Upload configurations
const UPLOAD_CONFIG = {
    maxFileSize: maxFileSize,
    toastDuration: 3000,
    transitionDelay: 300,
    fadeDelay: 50
};

// Global variables
let currentFileHash = null;
let currentFileExtension = null;
let isDriverFile = false;


document.addEventListener('DOMContentLoaded', function() {
    const elements = {
        dropZone: document.getElementById('dropZone'),
        fileInput: document.getElementById('fileInput'),
        uploadStatus: document.getElementById('uploadStatus'),
        uploadArea: document.getElementById('uploadArea'),
        fileAnalysisArea: document.getElementById('fileAnalysisArea'),
        fileName: document.getElementById('fileName'),
        fileSize: document.getElementById('fileSize'),
        fileType: document.getElementById('fileType'),
        fileFormat: document.getElementById('fileFormat'),
        fileCategory: document.getElementById('fileCategory'),
        fileEntropy: document.getElementById('fileEntropy'),
        uploadTime: document.getElementById('uploadTime'),
        md5Hash: document.getElementById('md5Hash'),
        sha256Hash: document.getElementById('sha256Hash'),
        fileSpecificInfo: document.getElementById('fileSpecificInfo'),
        step1Circle: document.getElementById('step1Circle'),
        step1Text: document.getElementById('step1Text'),
        step2Circle: document.getElementById('step2Circle'),
        step2Text: document.getElementById('step2Text'),
        progressLine: document.getElementById('progressLine'),
        toastContainer: document.getElementById('toastContainer'),
        entropyBar: document.getElementById('entropyBar'),
        entropyNotes: document.getElementById('entropyNotes'),
        detectionRisk: document.getElementById('detectionRisk'),
        peInfo: document.getElementById('peInfo'),
        sectionsList: document.getElementById('sectionsList'),
        detectionNotes: document.getElementById('detectionNotes'),
        officeInfo: document.getElementById('officeInfo'),
        macroStatus: document.getElementById('macroStatus'),
        macroDetectionNotes: document.getElementById('macroDetectionNotes'),
        htmlSmuggleInfo: document.getElementById('htmlSmuggleInfo'),
        smuggleStatus: document.getElementById('smuggleStatus'),
        smuggleDetectionNotes: document.getElementById('smuggleDetectionNotes'),
        smuggleInfo: document.getElementById('smuggleInfo'),
        checksumInfo: document.getElementById('checksumInfo'),
        checksumStatus: document.getElementById('checksumStatus'),
        storedChecksum: document.getElementById('storedChecksum'),
        calculatedChecksum: document.getElementById('calculatedChecksum'),
        checksumNotes: document.getElementById('checksumNotes'),
        suspiciousImports: document.getElementById('suspiciousImports'),
        suspiciousImportsList: document.getElementById('suspiciousImportsList'),
        suspiciousImportsCount: document.getElementById('suspiciousImportsCount'),
        suspiciousImportsSummary: document.getElementById('suspiciousImportsSummary'),
        suspiciousImportsTitle: document.getElementById('suspiciousImportsTitle'),
    };

    let dragCounter = 0;

    // Event Listeners
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        elements.dropZone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    elements.dropZone.addEventListener('dragenter', () => {
        dragCounter++;
        if (dragCounter === 1) highlight();
    });

    elements.dropZone.addEventListener('dragleave', () => {
        dragCounter--;
        if (dragCounter === 0) unhighlight();
    });

    elements.dropZone.addEventListener('drop', (e) => {
        dragCounter = 0;
        unhighlight();
        handleDrop(e);
    });

    elements.fileInput.addEventListener('change', handleFiles);

    // Utility Functions
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function highlight() {
        const label = elements.dropZone.querySelector('.lb-upload-zone');
        if (label) label.classList.add('lb-drag-over');
    }

    function unhighlight() {
        const label = elements.dropZone.querySelector('.lb-upload-zone');
        if (label) label.classList.remove('lb-drag-over');
    }

    function showToast(message, type = 'success') {
        const toast = document.createElement('div');
        const colors = {
            success: 'border-green-500/25 bg-green-500/10 text-green-300',
            error: 'border-red-500/25 bg-red-500/10 text-red-300',
            info: 'border-blue-500/25 bg-blue-500/10 text-blue-300'
        };

        toast.className = `flex items-center space-x-2 p-4 rounded-lg border ${colors[type]} transform translate-y-2 opacity-0 transition-all duration-300 text-base`;
        toast.innerHTML = `
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="${type === 'success' ? 'M5 13l4 4L19 7' : 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'}"/>
            </svg>
            <span>${message}</span>
        `;

        elements.toastContainer.appendChild(toast);
        requestAnimationFrame(() => {
            toast.classList.remove('translate-y-2', 'opacity-0');
        });

        setTimeout(() => {
            toast.classList.add('translate-y-2', 'opacity-0');
            setTimeout(() => toast.remove(), UPLOAD_CONFIG.fadeDelay);
        }, UPLOAD_CONFIG.toastDuration);
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function formatTimestamp(timestamp) {
        return new Date(timestamp).toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }

    function updateProgress(step, completed = false) {
        const stepCircle = step === 1 ? elements.step1Circle : elements.step2Circle;
        const stepText = step === 1 ? elements.step1Text : elements.step2Text;

        if (completed && step === 1) {
            stepCircle.classList.remove('bg-red-500/10', 'border-red-500', 'bg-red-500/8', 'border-red-500/40', 'bg-black/50', 'border-gray-700');
            stepCircle.classList.add('bg-green-500/8', 'border-green-500/40');

            stepText.innerHTML = `
                <svg class="w-5 h-5 text-green-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                </svg>
            `;

            elements.progressLine.classList.remove('to-gray-800');
            elements.progressLine.classList.add('to-red-500/15');

            elements.step2Circle.classList.remove('bg-black/50', 'border-gray-700');
            elements.step2Circle.classList.add('bg-red-500/8', 'border-red-500/40');
            elements.step2Text.classList.remove('text-gray-500');
            elements.step2Text.classList.add('text-red-300');
        }
    }

    // File type detection and UI updates.
    //
    // The analysis-mode selector is a single segmented control with one tab
    // per mode (Static / Dynamic / each EDR profile / HolyGrail). Each tab
    // is tagged with one or more `data-family` values (space-separated) and
    // only tabs matching the uploaded file's family are shown.
    //
    // Four families:
    //   driver  -- .sys (-> static-driver, holygrail)
    //   office  -- Word / Excel macro-bearing documents (-> static only;
    //              dynamic / EDR don't make sense without an Office install
    //              on the target host -- olevba is the relevant scanner)
    //   html    -- .html / .htm (-> static only; SmuggleShield-derived
    //              pattern analyzer runs at upload time as html_smuggle_info)
    //   regular -- everything else (-> all / static / dynamic / edr:*)
    const DRIVER_EXTS = new Set(['sys']);
    const OFFICE_EXTS = new Set([
        'docx', 'docm', 'dotm', 'doc', 'rtf',
        'xlsx', 'xlsm', 'xltm', 'xls',
    ]);
    const HTML_EXTS = new Set(['html', 'htm']);

    function updateAnalysisOptions(fileExtension) {
        const ext = (fileExtension || '').toLowerCase();
        isDriverFile = DRIVER_EXTS.has(ext);
        const family = isDriverFile ? 'driver'
                     : OFFICE_EXTS.has(ext) ? 'office'
                     : HTML_EXTS.has(ext)   ? 'html'
                     : 'regular';

        const tabs = document.querySelectorAll('#modeTabs .lb-tab');
        const bodies = document.querySelectorAll('.lb-mode-body');

        // Show only tabs whose `data-family` list contains this file's family.
        // Multiple families are space-separated (e.g. `regular office` for the
        // Static tab, which serves both classes).
        let firstVisible = null;
        tabs.forEach(t => {
            const families = (t.dataset.family || '').split(/\s+/);
            const matches = families.includes(family);
            t.classList.toggle('hidden', !matches);
            t.classList.remove('active');
            if (matches && !firstVisible) firstVisible = t;
        });

        if (firstVisible) {
            firstVisible.classList.add('active');
            // Hide all bodies, then show the one that matches.
            bodies.forEach(b => b.classList.add('hidden'));
            const target = document.querySelector(`.lb-mode-body[data-mode="${firstVisible.dataset.mode}"]`);
            if (target) target.classList.remove('hidden');
        }
    }

    // Wire tab clicks. Activating a tab swaps the active class and reveals
    // the matching mode body.
    document.getElementById('modeTabs').addEventListener('click', (e) => {
        const tab = e.target.closest('.lb-tab');
        if (!tab || tab.classList.contains('hidden')) return;
        document.querySelectorAll('#modeTabs .lb-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        document.querySelectorAll('.lb-mode-body').forEach(b => b.classList.add('hidden'));
        const target = document.querySelector(`.lb-mode-body[data-mode="${tab.dataset.mode}"]`);
        if (target) target.classList.remove('hidden');
    });

    function getDetectionRiskColor(risk) {
        const colors = {
            'High': 'bg-red-500/10 text-red-300 border border-red-500/25',
            'Medium': 'bg-yellow-500/10 text-yellow-300 border border-yellow-500/25',
            'Low': 'bg-green-500/10 text-green-300 border border-green-500/25'
        };
        return colors[risk] || colors['Low'];
    }

    // File Info Functions (all the existing functions remain the same)
    function renderFileTypeSpecificInfo(fileInfo) {
        elements.peInfo.classList.add('hidden');
        elements.officeInfo.classList.add('hidden');
        if (elements.htmlSmuggleInfo) elements.htmlSmuggleInfo.classList.add('hidden');
        elements.suspiciousImports.classList.add('hidden');

        if (fileInfo.entropy_analysis) {
            const entropyPercentage = (fileInfo.entropy / 8) * 100;
            elements.entropyBar.style.width = `${entropyPercentage}%`;
            elements.entropyBar.className = `absolute h-full transition-all duration-300 ${
                fileInfo.entropy_analysis.detection_risk === 'High' ? 'bg-red-400' :
                fileInfo.entropy_analysis.detection_risk === 'Medium' ? 'bg-yellow-400' : 'bg-green-400'
            }`;

            elements.detectionRisk.className = `px-3 py-1 text-sm rounded-full ${
                getDetectionRiskColor(fileInfo.entropy_analysis.detection_risk)
            }`;
            elements.detectionRisk.textContent = `${fileInfo.entropy_analysis.detection_risk} Detection Risk`;

            elements.entropyNotes.innerHTML = fileInfo.entropy_analysis.notes.map(note => `
                <div class="flex items-center space-x-2">
                    <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                            d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    <span>${note}</span>
                </div>
            `).join('');
        }

        if (fileInfo.pe_info) {
            elements.peInfo.classList.remove('hidden');
            const pe = fileInfo.pe_info;

            if (pe.suspicious_imports && pe.suspicious_imports.length > 0) {
                elements.suspiciousImports.classList.remove('hidden');
                
                const buildWith = pe.build_with || null;
                const runtimeConfig = getRuntimeConfig(buildWith);
                const runtimeImports = pe.suspicious_imports.filter(imp => imp.is_runtime_import);
                const genuinelySuspicious = pe.suspicious_imports.filter(imp => !imp.is_runtime_import);
                
                elements.suspiciousImportsTitle.textContent = runtimeConfig.title;
                elements.suspiciousImportsCount.className = `px-3 py-1 text-sm ${runtimeConfig.countClass} rounded-full`;
                elements.suspiciousImportsCount.textContent = `${pe.suspicious_imports.length} Found${runtimeConfig.badge ? ` (${runtimeConfig.badge})` : ''}`;
                
                elements.suspiciousImportsList.innerHTML = pe.suspicious_imports.map(imp => {
                    const isRuntimeImport = imp.is_runtime_import || false;
                    const config = isRuntimeImport ? runtimeConfig : getRuntimeConfig(null);
                    
                    return `
                        <div class="border-b border-gray-800 last:border-b-0 pb-3">
                            <div class="flex items-center justify-between mb-2">
                                <div class="flex items-center space-x-2">
                                    <span class="${config.dllColor} font-mono">${imp.dll}</span>
                                    <span class="text-gray-400">→</span>
                                    <span class="text-gray-300 font-mono">${imp.function}</span>
                                    <span class="ml-2 px-2 py-0.5 text-xs ${config.categoryBg} ${config.categoryText} rounded-full">[${imp.category || 'Unknown'}]</span>
                                    ${isRuntimeImport ? `<span class="ml-2 px-2 py-0.5 text-xs ${config.badgeBg} ${config.badgeText} rounded-full">${runtimeConfig.badgeLabel}</span>` : ''}
                                </div>
                                ${imp.hint !== null && imp.hint !== undefined ? `<span class="text-xs text-gray-500" title="Import hint: suggested index in DLL export table">Hint: ${imp.hint}</span>` : ''}
                            </div>
                            <div class="flex items-center space-x-2">
                                <svg class="w-4 h-4 ${config.iconColor}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                                </svg>
                                <span class="text-sm text-gray-400">${imp.note}</span>
                            </div>
                        </div>
                    `;
                }).join('');

                updateImportsSummary(buildWith, runtimeImports.length, genuinelySuspicious.length);
            }

            if (pe.checksum_info) {
                elements.checksumInfo.classList.remove('hidden');
                elements.storedChecksum.textContent = pe.checksum_info.stored_checksum;
                elements.calculatedChecksum.textContent = pe.checksum_info.calculated_checksum;
                
                const buildWith = pe.checksum_info.build_with;
                const isValid = pe.checksum_info.is_valid;
                
                if (isValid) {
                    elements.checksumStatus.className = 'px-3 py-1 text-sm rounded-full bg-green-500/8 text-green-300 border border-green-500/22';
                    elements.checksumStatus.textContent = 'Valid';
                } else if (buildWith) {
                    const runtimeConfig = getRuntimeConfig(buildWith);
                    elements.checksumStatus.className = `px-3 py-1 text-sm rounded-full ${runtimeConfig.checksumClass}`;
                    elements.checksumStatus.textContent = `${buildWith.charAt(0).toUpperCase() + buildWith.slice(1)} Binary`;
                } else {
                    elements.checksumStatus.className = 'px-3 py-1 text-sm rounded-full bg-red-500/8 text-red-300 border border-red-500/22';
                    elements.checksumStatus.textContent = 'Invalid';
                }
                
                if (!pe.checksum_info.is_valid) {
                    const buildWith = pe.checksum_info.build_with;
                    const runtimeConfig = getRuntimeConfig(buildWith);
                    
                    elements.checksumNotes.innerHTML = `
                        <div class="flex items-center space-x-2">
                            <svg class="w-4 h-4 ${runtimeConfig.iconColor}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                            </svg>
                            <span>${runtimeConfig.checksumNote}</span>
                        </div>
                    `;
                }
            } else {
                elements.checksumInfo.classList.add('hidden');
            }
            
            renderPEBasicInfo(pe);
        }
        else if (fileInfo.office_info) {
            elements.officeInfo.classList.remove('hidden');
            renderOfficeInfo(fileInfo.office_info);
        }
        else if (fileInfo.lnk_info) {
            // Show LNK-specific information section
            const lnkInfoSection = document.getElementById('lnkInfo') || createLnkInfoSection();
            lnkInfoSection.classList.remove('hidden');
            renderLnkInfo(fileInfo.lnk_info);
        }
        else if (fileInfo.html_smuggle_info) {
            const htmlSection = document.getElementById('htmlSmuggleInfo');
            if (htmlSection) htmlSection.classList.remove('hidden');
            renderHtmlSmuggleInfo(fileInfo.html_smuggle_info);
        }
    }

    // -- Office macro / template-injection rendering --------------------
    //
    // Surfaces every non-empty piece of the `office_info` structure:
    //   * Status pill: Macros Present / No Macros
    //   * Detection notes (one-line summaries)
    //   * Autoexec triggers           (table: keyword + description)
    //   * Suspicious keywords         (table: keyword + description)
    //   * IOCs                        (table: type + value)
    //   * External refs               (table: relationship + target -- T1221 etc.)
    //   * Per-module VBA source code  (collapsible <details>)
    //   * Hex / Base64 / VBA strings  (collapsible)
    //
    // The DOM container (#officeInfo) already exists in upload.html; this
    // function rewrites #macroDetectionNotes (status notes) and #macroInfo
    // (detail blocks) every time it runs.
    function escapeHtml(s) {
        return String(s ?? '').replace(/[&<>"']/g, c => (
            { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
        ));
    }

    function macroSeverityClass(office) {
        // Treat external attachedTemplate references and live macros as the
        // strong signals. Everything else goes "info".
        if (office.has_macros) return 'critical';
        if ((office.external_refs || []).some(r => r.relationship === 'attachedTemplate')) return 'critical';
        if ((office.external_refs || []).length > 0) return 'medium';
        return 'low';
    }

    function renderTable(headers, rows) {
        if (!rows.length) return '';
        const head = headers.map(h => `<th style="text-align:left;padding:4px 8px;border-bottom:1px solid var(--lb-border);font-size:11px;color:var(--lb-text-dim);text-transform:uppercase;letter-spacing:0.5px;">${escapeHtml(h)}</th>`).join('');
        const body = rows.map(r => `<tr>${r.map(c => `<td style="padding:4px 8px;font-size:12px;vertical-align:top;border-bottom:1px solid rgba(255,255,255,0.04);">${c}</td>`).join('')}</tr>`).join('');
        return `<table style="width:100%;border-collapse:collapse;margin:6px 0 12px 0;"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
    }

    function renderSection(title, body, opts) {
        opts = opts || {};
        if (!body) return '';
        const collapsible = opts.collapsible;
        const open = opts.open === undefined ? false : opts.open;
        const heading = `<div style="font-size:11px;color:var(--lb-text-dim);text-transform:uppercase;letter-spacing:0.5px;margin:14px 0 4px 0;">${escapeHtml(title)}</div>`;
        if (collapsible) {
            return `${heading}<details ${open ? 'open' : ''} style="border:1px solid var(--lb-border);padding:8px;border-radius:3px;background:rgba(255,255,255,0.02);"><summary style="cursor:pointer;font-size:12px;color:var(--lb-text);">${escapeHtml(opts.summary || 'show')}</summary>${body}</details>`;
        }
        return `${heading}${body}`;
    }

    function renderOfficeInfo(office) {
        // Status pill
        const sev = macroSeverityClass(office);
        const sevClassMap = {
            critical: 'bg-red-500/8 text-red-300 border border-red-500/22',
            medium:   'bg-yellow-500/8 text-yellow-300 border border-yellow-500/22',
            low:      'bg-green-500/8 text-green-300 border border-green-500/22',
        };
        elements.macroStatus.className = `px-3 py-1 text-sm rounded-full ${sevClassMap[sev]}`;
        elements.macroStatus.textContent = office.has_macros
            ? 'Macros Present'
            : ((office.external_refs || []).length > 0 ? 'External Refs' : 'No Macros');

        // Top-level detection notes (one-line summaries)
        const notes = office.detection_notes || [];
        elements.macroDetectionNotes.innerHTML = notes.map(note => `
            <div style="display:flex;align-items:flex-start;gap:6px;margin-bottom:3px;">
                <span style="color:var(--lb-warn);">⚠</span>
                <span>${escapeHtml(note)}</span>
            </div>
        `).join('');

        // Detailed sections
        const macroInfo = document.getElementById('macroInfo');
        if (!macroInfo) return;
        const parts = [];

        // External references (T1221 etc.) -- shown FIRST when present
        // since they're often the only signal for documents that have no VBA.
        const refs = office.external_refs || [];
        if (refs.length > 0) {
            const rows = refs.map(r => [
                `<span class="lb-tag ${r.relationship === 'attachedTemplate' ? 'critical' : 'medium'}">${escapeHtml(r.relationship)}</span>`,
                `<span class="lb-mono" style="word-break:break-all;font-size:11px;"><a href="${escapeHtml(r.target)}" target="_blank" rel="noopener noreferrer" style="color:var(--lb-accent-soft);">${escapeHtml(r.target)}</a></span>`,
                `<span class="lb-mono" style="font-size:11px;color:var(--lb-text-dim);">${escapeHtml(r.rels_file)}</span>`,
            ]);
            parts.push(renderSection('External References (Remote Targets)', renderTable(['Relationship', 'Target', 'In .rels'], rows)));
        }

        const a = office.analysis || {};

        // Autoexec triggers
        if ((a.autoexec || []).length > 0) {
            const rows = a.autoexec.map(e => [
                `<span class="lb-tag critical">${escapeHtml(e.keyword || '?')}</span>`,
                `<span style="font-size:12px;">${escapeHtml(e.description || '')}</span>`,
            ]);
            parts.push(renderSection(`Auto-Execution Triggers (${a.autoexec.length})`, renderTable(['Keyword', 'Description'], rows)));
        }

        // Suspicious keywords
        if ((a.suspicious || []).length > 0) {
            const rows = a.suspicious.map(e => [
                `<span class="lb-tag medium">${escapeHtml(e.keyword || '?')}</span>`,
                `<span style="font-size:12px;">${escapeHtml(e.description || '')}</span>`,
            ]);
            parts.push(renderSection(`Suspicious Keywords (${a.suspicious.length})`, renderTable(['Keyword', 'Description'], rows)));
        }

        // IOCs (URLs, IPs, EXEs, etc. that olevba pulled out of the macro body)
        if ((a.iocs || []).length > 0) {
            const rows = a.iocs.map(ioc => [
                `<span class="lb-tag info">${escapeHtml(ioc.type || '?')}</span>`,
                `<span class="lb-mono" style="word-break:break-all;font-size:11px;">${escapeHtml(ioc.value || '')}</span>`,
            ]);
            parts.push(renderSection(`IOCs Extracted from Macro (${a.iocs.length})`, renderTable(['Type', 'Value'], rows)));
        }

        // Hex / Base64 / VBA-encoded strings (decoded by olevba)
        const stringSets = [
            ['Hex Strings', a.hex_strings || []],
            ['Base64 Strings', a.base64_strings || []],
            ['VBA-Encoded Strings', a.vba_strings || []],
        ];
        for (const [label, items] of stringSets) {
            if (items.length === 0) continue;
            const body = items.map(e => `<div class="lb-mono" style="word-break:break-all;font-size:11px;padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.04);"><strong>${escapeHtml(e.keyword || '')}:</strong> ${escapeHtml(e.description || '')}</div>`).join('');
            parts.push(renderSection(`${label} (${items.length})`, body, { collapsible: true, summary: `${items.length} item(s) -- click to expand` }));
        }

        // Per-module VBA source code -- collapsible
        const modules = office.modules || [];
        if (modules.length > 0) {
            const body = modules.map(m => `
                <div style="margin-top:8px;">
                    <div style="font-size:12px;color:var(--lb-text);margin-bottom:4px;">
                        <span class="lb-mono" style="color:var(--lb-accent-soft);">${escapeHtml(m.vba_filename || '?')}</span>
                        <span class="lb-muted" style="font-size:11px;"> -- ${escapeHtml(m.stream || '')}</span>
                    </div>
                    <pre style="background:rgba(0,0,0,0.3);padding:8px;border:1px solid var(--lb-border);font-size:11px;overflow-x:auto;max-height:240px;overflow-y:auto;white-space:pre-wrap;color:var(--lb-text);">${escapeHtml(m.code || '')}</pre>
                </div>
            `).join('');
            parts.push(renderSection(`VBA Source (${modules.length} module${modules.length !== 1 ? 's' : ''})`, body, { collapsible: true, summary: `${modules.length} module(s) -- click to view source code` }));
        }

        macroInfo.innerHTML = parts.join('');
    }

    // -- HTML smuggling rendering --------------------------------------
    //
    // Surfaces every non-empty piece of the `html_smuggle_info` structure
    // produced by app/utils/htmlsmuggle.py:
    //   * Status pill: SMUGGLING / SUSPICIOUS / CLEAN with score
    //   * Detection notes (one-line summaries)
    //   * Score bar + matched-categories pill row
    //   * Matched patterns         (table: name + category + weight)
    //   * Surface features         (table: feature + value)
    //   * IOCs                     (download filenames, dataset blobs, largest base64 preview)
    //
    // Reuses the renderTable / renderSection / escapeHtml helpers defined
    // for the office macro renderer.
    function smuggleSeverityClass(h) {
        if (h.is_smuggling) return 'critical';
        if ((h.score || 0) > 0) return 'medium';
        return 'low';
    }

    function renderHtmlSmuggleInfo(h) {
        // Status pill
        const sev = smuggleSeverityClass(h);
        const sevClassMap = {
            critical: 'bg-red-500/8 text-red-300 border border-red-500/22',
            medium:   'bg-yellow-500/8 text-yellow-300 border border-yellow-500/22',
            low:      'bg-green-500/8 text-green-300 border border-green-500/22',
        };
        if (elements.smuggleStatus) {
            elements.smuggleStatus.className = `px-3 py-1 text-sm rounded-full ${sevClassMap[sev]}`;
            const label = h.is_smuggling
                ? `SMUGGLING (score ${h.score}/${h.threshold})`
                : (h.score > 0 ? `SUSPICIOUS (score ${h.score}/${h.threshold})` : 'CLEAN');
            elements.smuggleStatus.textContent = label;
        }

        // Detection notes
        const notes = h.detection_notes || [];
        if (elements.smuggleDetectionNotes) {
            elements.smuggleDetectionNotes.innerHTML = notes.map(note => `
                <div style="display:flex;align-items:flex-start;gap:6px;margin-bottom:3px;">
                    <span style="color:var(--lb-warn);">⚠</span>
                    <span>${escapeHtml(note)}</span>
                </div>
            `).join('');
        }

        // Detail blocks
        const host = elements.smuggleInfo;
        if (!host) return;
        const parts = [];

        // Score line + matched-category pills
        const cats = h.matched_categories || {};
        if (Object.keys(cats).length > 0) {
            const pills = Object.entries(cats).map(([cat, count]) =>
                `<span class="lb-tag medium" style="margin-right:4px;">${escapeHtml(cat)} × ${count}</span>`
            ).join(' ');
            parts.push(renderSection('Pattern Categories', `<div style="padding:4px 0;">${pills}</div>`));
        }

        // Matched patterns -- the actual signatures that fired
        const matches = h.matched_patterns || [];
        if (matches.length > 0) {
            const rows = matches.map(m => [
                `<span class="lb-mono" style="font-size:11px;">${escapeHtml(m.name)}</span>`,
                `<span class="lb-tag info">${escapeHtml(m.category || '?')}</span>`,
                `<span class="lb-mono" style="font-size:11px;">+${m.weight || 0}</span>`,
            ]);
            parts.push(renderSection(`Matched Patterns (${matches.length})`, renderTable(['Pattern', 'Category', 'Weight'], rows)));
        }

        // Surface features
        const f = h.features || {};
        if (Object.keys(f).length > 0) {
            const featureRows = [
                ['File size (bytes)', f.file_size],
                ['Script tags', f.script_tags],
                ['iframe tags', f.iframe_tags],
                ['embed tags', f.embed_tags],
                ['Base64 blob count (>=50 chars)', f.base64_blob_count],
                ['Largest base64 blob (chars)', f.largest_base64_chars],
                ['Has blob()', f.has_blob],
                ['Has atob()', f.has_atob],
                ['Has Uint8Array', f.has_uint8array],
                ['Has URL.createObjectURL', f.has_createobjecturl],
                ['Has <a download="...">', f.has_download_attr],
                ['Has String.fromCharCode', f.has_fromcharcode],
            ].filter(([, v]) => v !== undefined && v !== null && v !== false && v !== 0)
             .map(([label, v]) => [
                `<span style="font-size:12px;">${escapeHtml(label)}</span>`,
                `<span class="lb-mono" style="font-size:12px;">${escapeHtml(String(v))}</span>`,
             ]);
            if (featureRows.length > 0) {
                parts.push(renderSection('Surface Features', renderTable(['Feature', 'Value'], featureRows)));
            }
        }

        // IOCs
        const iocs = h.iocs || {};
        const iocBits = [];
        if ((iocs.download_filenames || []).length > 0) {
            const rows = iocs.download_filenames.map(name => [
                `<span class="lb-tag medium">download=</span>`,
                `<span class="lb-mono" style="word-break:break-all;font-size:11px;">${escapeHtml(name)}</span>`,
            ]);
            iocBits.push(renderTable(['Type', 'Value'], rows));
        }
        if ((iocs.data_file_attrs || []).length > 0) {
            const rows = iocs.data_file_attrs.map(d => [
                `<span class="lb-tag medium">data-file=</span>`,
                `<span class="lb-mono" style="word-break:break-all;font-size:11px;">${escapeHtml(d)}</span>`,
            ]);
            iocBits.push(renderTable(['Type', 'Value (truncated)'], rows));
        }
        if (iocs.largest_base64_blob && iocs.largest_base64_blob.length > 0) {
            const b = iocs.largest_base64_blob;
            iocBits.push(`
                <div class="lb-mono" style="font-size:11px;padding:4px 0;">
                    <div><strong>Largest base64 blob:</strong> ${b.length} chars</div>
                    <div style="margin-top:4px;color:var(--lb-text-dim);">First 120: <span style="color:var(--lb-text);word-break:break-all;">${escapeHtml(b.preview_first_120)}</span></div>
                    ${b.preview_last_120 ? `<div style="margin-top:4px;color:var(--lb-text-dim);">Last 120: <span style="color:var(--lb-text);word-break:break-all;">${escapeHtml(b.preview_last_120)}</span></div>` : ''}
                </div>
            `);
        }
        if (iocBits.length > 0) {
            parts.push(renderSection('IOCs', iocBits.join('')));
        }

        if (h.truncated) {
            parts.push(`<div class="lb-muted" style="font-size:11px;margin-top:8px;">⚠ Scan was truncated -- file exceeds the 5 MiB cap.</div>`);
        }

        host.innerHTML = parts.join('');
    }

    function getRuntimeConfig(buildWith) {
        const configs = {
            'go': {
                title: 'API Imports Analysis (Go Runtime)',
                badge: 'Go Runtime',
                badgeLabel: 'Go Runtime',
                countClass: 'bg-blue-500/5 text-blue-300',
                dllColor: 'text-blue-300',
                categoryBg: 'bg-blue-500/10',
                categoryText: 'text-blue-300',
                badgeBg: 'bg-gray-500/10',
                badgeText: 'text-gray-400',
                iconColor: 'text-blue-400',
                checksumClass: 'bg-blue-500/5 text-blue-300',
                checksumNote: 'Go binaries typically have non-standard PE checksums - This is normal behavior'
            },
            'rust': {
                title: 'API Imports Analysis (Rust Runtime)',
                badge: 'Rust Runtime',
                badgeLabel: 'Rust Runtime',
                countClass: 'bg-purple-500/5 text-purple-300',
                dllColor: 'text-purple-300',
                categoryBg: 'bg-purple-500/10',
                categoryText: 'text-purple-300',
                badgeBg: 'bg-gray-500/10',
                badgeText: 'text-gray-400',
                iconColor: 'text-purple-400',
                checksumClass: 'bg-purple-500/5 text-purple-300',
                checksumNote: 'Rust binaries may have non-standard PE checksums - This is normal behavior'
            }
        };

        const defaultConfig = {
            title: 'Sensitive Imports Analysis',
            badge: null,
            badgeLabel: 'Sensitive',
            countClass: 'bg-red-500/5 text-red-300',
            dllColor: 'text-red-300',
            categoryBg: 'bg-red-500/10',
            categoryText: 'text-red-300',
            badgeBg: 'bg-red-500/10',
            badgeText: 'text-red-300',
            iconColor: 'text-yellow-400',
            checksumClass: 'bg-red-500/5 text-red-300',
            checksumNote: 'Invalid checksum - Common in packed/modified payloads'
        };
        
        return configs[buildWith] || defaultConfig;
    }

    function renderPEBasicInfo(pe) {
        const html = `
            <div class="space-y-4">
                <div class="flex items-center justify-between">
                    <h6 class="text-base font-medium text-gray-300">PE File Information</h6>
                    <span class="text-sm text-gray-400">File Type: ${pe.file_type}</span>
                    <span class="text-sm text-gray-400">Compile Time: ${pe.compile_time}</span>
                </div>
                <div class="grid grid-cols-3 gap-4">
                    <div>
                        <div class="text-base text-gray-400 mb-1">Machine Type</div>
                        <div class="text-base text-gray-300">${pe.machine_type}</div>
                    </div>
                    <div>
                        <div class="text-base text-gray-400 mb-1">Subsystem</div>
                        <div class="text-base text-gray-300">${pe.subsystem}</div>
                    </div>
                    <div>
                        <div class="text-base text-gray-400 mb-1">Entry Point</div>
                        <div class="text-base font-mono text-gray-300">${pe.entry_point}</div>
                    </div>
                </div>
                <div class="space-y-2">
                    <div class="flex items-center justify-between">
                        <span class="text-base text-gray-400">PE Sections</span>
                        <span class="text-sm text-gray-400">${pe.sections.length} sections</span>
                    </div>
                    <div class="flex flex-wrap gap-2">
                        ${pe.sections.map(section => {
                            const isStandardSection = ['.text', '.data', '.bss', '.rdata', '.edata', '.idata', '.pdata', '.reloc', '.rsrc', '.tls', '.debug'].includes(section.name);
                            return `
                                <span class="px-2 py-1 text-sm ${isStandardSection ? 'bg-gray-900/50 text-gray-400' : 'bg-red-500/8 text-red-300'} rounded-lg border ${isStandardSection ? 'border-gray-800' : 'border-red-500/22'}">
                                    ${section.name}
                                </span>
                            `;
                        }).join('')}
                    </div>
                </div>
                ${pe.imports && pe.imports.length > 0 ? `
                    <div class="space-y-2">
                        <div class="flex items-center justify-between">
                            <span class="text-base text-gray-400">Imported DLLs</span>
                            <span class="text-sm text-gray-400">${pe.imports.length} imports</span>
                        </div>
                        <div class="flex flex-wrap gap-2">
                            ${pe.imports.map(imp => `
                                <span class="px-2 py-1 text-sm bg-gray-900/50 rounded-lg border border-gray-800 text-gray-400">
                                    ${imp}
                                </span>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
        
        elements.fileSpecificInfo.innerHTML = html;
    }

    function updateImportsSummary(buildWith, runtimeCount, suspiciousCount) {
        let summaryText = '';

        if (buildWith === 'go') {
            if (suspiciousCount > 0) {
                summaryText = `Go binary detected: ${runtimeCount} standard Go runtime imports and ${suspiciousCount} sensitive imports observed.`;
            } else {
                summaryText = `Go binary detected: ${runtimeCount} standard Go runtime imports — typically not user logic.`;
            }
        } else if (buildWith === 'rust') {
            if (suspiciousCount > 0) {
                summaryText = `Rust binary detected: ${runtimeCount} standard Rust runtime imports and ${suspiciousCount} sensitive imports observed.`;
            } else {
                summaryText = `Rust binary detected: ${runtimeCount} standard Rust runtime imports — typically not user logic.`;
            }
        } else {
            const totalImports = runtimeCount + suspiciousCount;
            summaryText = `${totalImports} sensitive imports observed — these are APIs commonly watched by AV/EDR.`;
        }

        elements.suspiciousImportsSummary.textContent = summaryText;
    }

    function updateFileInfo(fileInfo) {
        currentFileHash = fileInfo.md5;
        currentFileExtension = fileInfo.extension;

        elements.fileName.textContent = fileInfo.original_name;
        elements.fileSize.textContent = formatFileSize(fileInfo.size);
        elements.fileType.textContent = fileInfo.extension.toUpperCase();
        elements.fileFormat.textContent = fileInfo.mime_type;
        elements.fileCategory.textContent = fileInfo.extension.toUpperCase();
        elements.fileEntropy.textContent = fileInfo.entropy;
        elements.uploadTime.textContent = formatTimestamp(fileInfo.upload_time);
        elements.md5Hash.textContent = fileInfo.md5;

        elements.sha256Hash.textContent = `${fileInfo.sha256.substring(0, 32)}...`;
        document.getElementById('sha256HashFull').textContent = fileInfo.sha256;
        localStorage.setItem('currentFileExtension', fileInfo.extension);

        // Update analysis options based on file type
        updateAnalysisOptions(fileInfo.extension);

        renderFileTypeSpecificInfo(fileInfo);

        elements.uploadArea.classList.add('opacity-0', 'scale-95');
        setTimeout(() => {
            elements.uploadArea.classList.add('hidden');
            elements.fileAnalysisArea.classList.remove('hidden');
            setTimeout(() => {
                elements.fileAnalysisArea.classList.remove('opacity-0', 'scale-95');
            }, UPLOAD_CONFIG.fadeDelay);
        }, UPLOAD_CONFIG.transitionDelay);

        updateProgress(1, true);
    }

    // File Handling Functions
    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;

        if (files.length > 1) {
            showToast('Please upload only one file at a time', 'error');
            return;
        }

        handleFiles({ target: { files } });
    }

    function handleFiles(e) {
        const file = e.target.files[0];
        if (!file) return;

        const extension = file.name.split('.').pop().toLowerCase();
        const allowedExtensions = (window.serverConfig && window.serverConfig.allowedExtensions) || [];

        if (!allowedExtensions.includes(extension)) {
            showToast(`Unsupported file type. Allowed types: ${allowedExtensions.map(e => '.' + e).join(', ')}`, 'error');
            return;
        }

        if (file.size > UPLOAD_CONFIG.maxFileSize) {
            showToast('File size exceeds limit', 'error');
            return;
        }

        uploadFile(file);
    }

    function uploadFile(file) {
        showToast('Uploading file...', 'info');

        const formData = new FormData();
        formData.append('file', file);

        fetch('/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) throw new Error(data.error);

            showToast('File uploaded successfully', 'success');
            if (data.file_info) updateFileInfo(data.file_info);
        })
        .catch(error => {
            showToast(error.message, 'error');
        });
    }

    // Global Functions
    window.copyHash = function(elementId) {
        const hashType = elementId === 'md5Hash' ? 'md5' : 'sha256';
        const fullHash = document.getElementById(`${hashType}HashFull`).textContent;

        navigator.clipboard.writeText(fullHash).then(() => {
            showToast(`${hashType.toUpperCase()} hash copied to clipboard`, 'success');
        });
    }

    window.selectAnalysisType = function(type) {
        if (!currentFileHash) return;

        updateProgress(2, true);
        elements.fileAnalysisArea.classList.add('opacity-0', 'scale-95');

        setTimeout(() => {
            if (type === 'holygrail') {
                // Show loading message
                showToast('Starting HolyGrail BYOVD analysis...', 'info');
                
                // Call HolyGrail analysis endpoint
                fetch(`/holygrail?hash=${currentFileHash}`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        showToast('HolyGrail analysis completed successfully', 'success');
                        // Redirect to results page
                        setTimeout(() => {
                            window.location.href = `/results/byovd/${currentFileHash}`;
                        }, 1000);
                    } else {
                        // Handle error
                        showToast(`Analysis failed: ${data.error || data.message}`, 'error');
                        // Reset UI
                        elements.fileAnalysisArea.classList.remove('opacity-0', 'scale-95');
                    }
                })
                .catch(error => {
                    console.error('HolyGrail analysis error:', error);
                    showToast(`Analysis failed: ${error.message}`, 'error');
                    // Reset UI
                    elements.fileAnalysisArea.classList.remove('opacity-0', 'scale-95');
                });
                
            } else if (type === 'all') {
                // "All" pipeline: static + (every registered EDR) in parallel,
                // then dynamic. Args (if any) shared across dynamic + EDR.
                const argsInput = document.getElementById('allAnalysisArgs');
                const argsValue = argsInput ? argsInput.value : '';
                const args = argsValue.split(' ').filter(arg => arg.trim() !== '');
                localStorage.setItem('analysisArgs', JSON.stringify(args));
                window.location.href = `/analyze/all/${currentFileHash}`;
            } else if (type === 'dynamic') {
                // Get user-specified arguments for dynamic analysis
                const argsInput = document.getElementById('analysisArgs').value;
                const args = argsInput.split(' ').filter(arg => arg.trim() !== '');

                // Save arguments to localStorage
                localStorage.setItem('analysisArgs', JSON.stringify(args));

                // Navigate to dynamic analysis
                window.location.href = `/analyze/${type}/${currentFileHash}`;
            } else if (type.startsWith('edr:')) {
                // EDR profile dispatch: type is "edr:<profile_name>".
                // Each profile body has its own args input (id =
                // edrArgs-<profile>); read it, persist to localStorage so
                // the results page's POST forwards it to Whiskers.
                const profile = type.slice(4);
                const argsInput = document.getElementById(`edrArgs-${profile}`);
                const argsValue = argsInput ? argsInput.value : '';
                const args = argsValue.split(' ').filter(arg => arg.trim() !== '');
                localStorage.setItem('analysisArgs', JSON.stringify(args));
                window.location.href = `/analyze/edr/${encodeURIComponent(profile)}/${currentFileHash}`;
            } else {
                // Navigate to static analysis
                window.location.href = `/analyze/${type}/${currentFileHash}`;
            }
        }, UPLOAD_CONFIG.transitionDelay);
    };

});