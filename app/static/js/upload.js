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


function createLnkInfoSection() {
    // Create LNK info section if it doesn't exist
    const lnkInfoSection = document.createElement('div');
    lnkInfoSection.id = 'lnkInfo';
    lnkInfoSection.className = 'bg-gray-900/30 rounded-lg p-4 hidden';
    
    // Insert after office info section
    const officeInfo = document.getElementById('officeInfo');
    officeInfo.parentNode.insertBefore(lnkInfoSection, officeInfo.nextSibling);
    
    return lnkInfoSection;
}

function renderLnkInfo(lnkInfo) {
    const lnkSection = document.getElementById('lnkInfo');
    
    const targetInfo = lnkInfo.target_info || {};
    const machineTracking = lnkInfo.machine_tracking || {};
    const lnkHeader = lnkInfo.lnk_header || {};
    const volumeInfo = lnkInfo.volume_info || {};
    const linkFlags = lnkInfo.link_flags || {};
    const fileAttributes = lnkInfo.file_attributes || {};
    
    // Calculate risk level based on target command
    const riskLevel = calculateLnkRisk(targetInfo.target_command);
    
    const html = `
        <div class="space-y-6">
            <!-- LNK Header -->
            <div class="flex items-center justify-between mb-4">
                <h4 class="text-lg font-medium text-gray-200">Windows LNK Shortcut Analysis</h4>
                <span class="px-3 py-1 text-sm rounded-full ${getRiskLevelClass(riskLevel)}">
                    ${riskLevel} Risk
                </span>
            </div>
            
            <!-- Target Command (Most Important) -->
            <div class="bg-black/40 rounded-lg p-4 border-l-4 ${getTargetCommandBorderClass(riskLevel)}">
                <div class="flex items-center space-x-2 mb-2">
                    <svg class="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3"/>
                    </svg>
                    <span class="text-base font-medium text-gray-200">Target Command</span>
                </div>
                <div class="font-mono text-sm ${getTargetCommandTextClass(riskLevel)} bg-gray-900/50 rounded p-3 break-all">
                    ${targetInfo.target_command || 'No target command found'}
                </div>
                ${targetInfo.command_line_arguments ? `
                    <div class="mt-2">
                        <span class="text-sm text-gray-400">Arguments: </span>
                        <span class="font-mono text-sm text-gray-300">${targetInfo.command_line_arguments}</span>
                    </div>
                ` : ''}
            </div>
            
            <!-- Target Details -->
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-3">
                    <div class="bg-gray-800/30 rounded-lg p-3">
                        <div class="text-sm text-gray-400 mb-1">Working Directory</div>
                        <div class="text-sm font-mono text-gray-300 break-all">
                            ${targetInfo.working_directory || 'Not specified'}
                        </div>
                    </div>
                    <div class="bg-gray-800/30 rounded-lg p-3">
                        <div class="text-sm text-gray-400 mb-1">Relative Path</div>
                        <div class="text-sm font-mono text-gray-300 break-all">
                            ${targetInfo.relative_path || 'Not specified'}
                        </div>
                    </div>
                </div>
                <div class="space-y-3">
                    <div class="bg-gray-800/30 rounded-lg p-3">
                        <div class="text-sm text-gray-400 mb-1">Icon Location</div>
                        <div class="text-sm font-mono text-gray-300 break-all">
                            ${targetInfo.icon_location || 'Default'}
                        </div>
                    </div>
                    <div class="bg-gray-800/30 rounded-lg p-3">
                        <div class="text-sm text-gray-400 mb-1">Window Style</div>
                        <div class="text-sm text-gray-300">
                            ${lnkHeader.window_style || 'Unknown'}
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Machine Tracking (Forensics) -->
            ${machineTracking.machine_identifier ? `
                <div class="bg-gray-800/30 rounded-lg p-4">
                    <div class="flex items-center space-x-2 mb-3">
                        <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
                        </svg>
                        <span class="text-base font-medium text-gray-200">Machine Tracking</span>
                    </div>
                    <div class="grid grid-cols-1 gap-3">
                        <div>
                            <div class="text-sm text-gray-400 mb-1">Machine Identifier</div>
                            <div class="text-sm font-mono text-blue-400 bg-blue-500/10 rounded px-2 py-1">
                                ${machineTracking.machine_identifier}
                            </div>
                        </div>
                        <div class="grid grid-cols-2 gap-3">
                            <div>
                                <div class="text-sm text-gray-400 mb-1">DROID Volume ID</div>
                                <div class="text-xs font-mono text-gray-300 bg-gray-900/50 rounded px-2 py-1 break-all">
                                    ${machineTracking.droid_volume_identifier || 'N/A'}
                                </div>
                            </div>
                            <div>
                                <div class="text-sm text-gray-400 mb-1">DROID File ID</div>
                                <div class="text-xs font-mono text-gray-300 bg-gray-900/50 rounded px-2 py-1 break-all">
                                    ${machineTracking.droid_file_identifier || 'N/A'}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            ` : ''}
            
            <!-- Timestamps -->
            <div class="bg-gray-800/30 rounded-lg p-4">
                <div class="flex items-center space-x-2 mb-3">
                    <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    <span class="text-base font-medium text-gray-200">Timestamps</span>
                </div>
                <div class="grid grid-cols-3 gap-4">
                    <div>
                        <div class="text-sm text-gray-400 mb-1">Created</div>
                        <div class="text-sm text-gray-300">
                            ${lnkHeader.creation_time || 'Unknown'}
                        </div>
                    </div>
                    <div>
                        <div class="text-sm text-gray-400 mb-1">Modified</div>
                        <div class="text-sm text-gray-300">
                            ${lnkHeader.modified_time || 'Unknown'}
                        </div>
                    </div>
                    <div>
                        <div class="text-sm text-gray-400 mb-1">Accessed</div>
                        <div class="text-sm text-gray-300">
                            ${lnkHeader.accessed_time || 'Unknown'}
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Volume Information -->
            ${volumeInfo.drive_type ? `
                <div class="bg-gray-800/30 rounded-lg p-4">
                    <div class="flex items-center space-x-2 mb-3">
                        <svg class="w-5 h-5 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/>
                        </svg>
                        <span class="text-base font-medium text-gray-200">Volume Information</span>
                    </div>
                    <div class="grid grid-cols-3 gap-4">
                        <div>
                            <div class="text-sm text-gray-400 mb-1">Drive Type</div>
                            <div class="text-sm text-gray-300">${volumeInfo.drive_type}</div>
                        </div>
                        <div>
                            <div class="text-sm text-gray-400 mb-1">Drive Serial</div>
                            <div class="text-sm font-mono text-gray-300">${volumeInfo.drive_serial || 'Unknown'}</div>
                        </div>
                        <div>
                            <div class="text-sm text-gray-400 mb-1">Local Base Path</div>
                            <div class="text-sm font-mono text-gray-300 break-all">${volumeInfo.local_base_path || 'N/A'}</div>
                        </div>
                    </div>
                </div>
            ` : ''}
            
            <!-- Technical Details -->
            <div class="grid grid-cols-2 gap-4">
                <div class="bg-gray-800/30 rounded-lg p-4">
                    <div class="text-sm font-medium text-gray-200 mb-3">Link Flags</div>
                    <div class="text-xs text-gray-400 mb-2">Raw Value: ${linkFlags.raw_value || 'N/A'}</div>
                    <div class="space-y-1">
                        ${(linkFlags.enabled_flags || []).map(flag => `
                            <div class="text-xs text-gray-300 bg-blue-500/10 rounded px-2 py-1 inline-block mr-1 mb-1">
                                ${flag}
                            </div>
                        `).join('')}
                    </div>
                </div>
                <div class="bg-gray-800/30 rounded-lg p-4">
                    <div class="text-sm font-medium text-gray-200 mb-3">File Attributes</div>
                    <div class="text-xs text-gray-400 mb-2">Raw Value: ${fileAttributes.raw_value || 'N/A'}</div>
                    <div class="space-y-1">
                        ${(fileAttributes.enabled_attributes || []).map(attr => `
                            <div class="text-xs text-gray-300 bg-green-500/10 rounded px-2 py-1 inline-block mr-1 mb-1">
                                ${attr.replace('FILE_ATTRIBUTE_', '')}
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        </div>
    `;
    
    lnkSection.innerHTML = html;
}

function calculateLnkRisk(targetCommand) {
    if (!targetCommand) return 'Low';
    
    const command = targetCommand.toLowerCase();
    
    // Critical indicators
    const criticalIndicators = [
        'powershell.exe -exec bypass',
        'powershell.exe -windowstyle hidden',
        'powershell.exe -encodedcommand',
        'cmd.exe /c powershell',
        'rundll32.exe javascript:',
        'regsvr32.exe /s /u /i:',
        'mshta.exe http',
        'certutil.exe -decode'
    ];
    
    // High risk indicators
    const highRiskIndicators = [
        'powershell.exe',
        'cmd.exe /c',
        'rundll32.exe',
        'regsvr32.exe',
        'mshta.exe',
        'wscript.exe',
        'cscript.exe'
    ];
    
    // Medium risk indicators
    const mediumRiskIndicators = [
        'http://',
        'https://',
        '.bat',
        '.cmd',
        '.vbs',
        '.js',
        '.ps1',
        'temp\\',
        '%appdata%',
        '%temp%'
    ];
    
    // Check for critical threats
    for (const indicator of criticalIndicators) {
        if (command.includes(indicator)) {
            return 'Critical';
        }
    }
    
    // Check for high-risk threats
    for (const indicator of highRiskIndicators) {
        if (command.includes(indicator)) {
            return 'High';
        }
    }
    
    // Check for medium-risk threats
    for (const indicator of mediumRiskIndicators) {
        if (command.includes(indicator)) {
            return 'Medium';
        }
    }
    
    return 'Low';
}

function getRiskLevelClass(riskLevel) {
    const classes = {
        'Critical': 'bg-red-500/20 text-red-400 border border-red-900/20',
        'High': 'bg-orange-500/20 text-orange-400 border border-orange-900/20',
        'Medium': 'bg-yellow-500/20 text-yellow-400 border border-yellow-900/20',
        'Low': 'bg-green-500/20 text-green-400 border border-green-900/20'
    };
    return classes[riskLevel] || classes['Low'];
}

function getTargetCommandBorderClass(riskLevel) {
    const classes = {
        'Critical': 'border-red-500',
        'High': 'border-orange-500',
        'Medium': 'border-yellow-500',
        'Low': 'border-green-500'
    };
    return classes[riskLevel] || classes['Low'];
}

function getTargetCommandTextClass(riskLevel) {
    const classes = {
        'Critical': 'text-red-400',
        'High': 'text-orange-400',
        'Medium': 'text-yellow-400',
        'Low': 'text-green-400'
    };
    return classes[riskLevel] || classes['Low'];
}

// Initialize when DOM is loaded
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
        // Analysis option containers
        regularAnalysisOptions: document.getElementById('regularAnalysisOptions'),
        driverAnalysisOptions: document.getElementById('driverAnalysisOptions'),
        argsInputContainer: document.getElementById('argsInputContainer')
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
        const label = elements.dropZone.querySelector('label');
        const icon = elements.dropZone.querySelector('.upload-icon');

        label.classList.add('scale-[1.02]', 'border-red-500/50');
        icon.classList.add('scale-110');
    }

    function unhighlight() {
        const label = elements.dropZone.querySelector('label');
        const icon = elements.dropZone.querySelector('.upload-icon');

        label.classList.remove('scale-[1.02]', 'border-red-500/50');
        icon.classList.remove('scale-110');
    }

    function showToast(message, type = 'success') {
        const toast = document.createElement('div');
        const colors = {
            success: 'border-green-900/20 bg-green-500/10 text-green-500',
            error: 'border-red-900/20 bg-red-500/10 text-red-500',
            info: 'border-blue-900/20 bg-blue-500/10 text-blue-500'
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
            stepCircle.classList.remove('bg-red-500/10', 'border-red-500', 'bg-black/50', 'border-gray-700');
            stepCircle.classList.add('bg-green-500/10', 'border-green-500');

            stepText.innerHTML = `
                <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                </svg>
            `;

            elements.progressLine.classList.remove('to-gray-800');
            elements.progressLine.classList.add('to-red-500/20');

            elements.step2Circle.classList.remove('bg-black/50', 'border-gray-700');
            elements.step2Circle.classList.add('bg-red-500/10', 'border-red-500');
            elements.step2Text.classList.remove('text-gray-500');
            elements.step2Text.classList.add('text-red-500');
        }
    }

    // File type detection and UI updates
    function updateAnalysisOptions(fileExtension) {
        isDriverFile = fileExtension.toLowerCase() === 'sys';
        
        if (isDriverFile) {
            // Show driver analysis options
            elements.regularAnalysisOptions.classList.add('hidden');
            elements.driverAnalysisOptions.classList.remove('hidden');
            // Hide command line arguments for driver files
            elements.argsInputContainer.classList.add('hidden');
        } else {
            // Show regular payload analysis options
            elements.driverAnalysisOptions.classList.add('hidden');
            elements.regularAnalysisOptions.classList.remove('hidden');
            // Show command line arguments for regular payloads
            elements.argsInputContainer.classList.remove('hidden');
        }
    }

    function getDetectionRiskColor(risk) {
        const colors = {
            'High': 'bg-red-500/10 text-red-500',
            'Medium': 'bg-yellow-500/10 text-yellow-500',
            'Low': 'bg-green-500/10 text-green-500'
        };
        return colors[risk] || colors['Low'];
    }

    // File Info Functions (all the existing functions remain the same)
    function renderFileTypeSpecificInfo(fileInfo) {
        elements.peInfo.classList.add('hidden');
        elements.officeInfo.classList.add('hidden');
        elements.suspiciousImports.classList.add('hidden');
        
        if (fileInfo.entropy_analysis) {
            const entropyPercentage = (fileInfo.entropy / 8) * 100;
            elements.entropyBar.style.width = `${entropyPercentage}%`;
            elements.entropyBar.className = `absolute h-full transition-all duration-300 ${
                fileInfo.entropy_analysis.detection_risk === 'High' ? 'bg-red-500' :
                fileInfo.entropy_analysis.detection_risk === 'Medium' ? 'bg-yellow-500' : 'bg-green-500'
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
                    elements.checksumStatus.className = 'px-3 py-1 text-sm rounded-full bg-green-500/10 text-green-500';
                    elements.checksumStatus.textContent = 'Valid';
                } else if (buildWith) {
                    const runtimeConfig = getRuntimeConfig(buildWith);
                    elements.checksumStatus.className = `px-3 py-1 text-sm rounded-full ${runtimeConfig.checksumClass}`;
                    elements.checksumStatus.textContent = `${buildWith.charAt(0).toUpperCase() + buildWith.slice(1)} Binary`;
                } else {
                    elements.checksumStatus.className = 'px-3 py-1 text-sm rounded-full bg-red-500/10 text-red-500';
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
            const office = fileInfo.office_info;

            elements.macroStatus.className = `px-3 py-1 text-sm rounded-full ${
                office.has_macros ? 'bg-red-500/10 text-red-500' : 'bg-green-500/10 text-green-500'
            }`;
            elements.macroStatus.textContent = office.has_macros ? 'Macros Present' : 'No Macros';

            if (office.detection_notes && office.detection_notes.length > 0) {
                elements.macroDetectionNotes.innerHTML = office.detection_notes.map(note => `
                    <div class="flex items-center space-x-2">
                        <svg class="w-4 h-4 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                        </svg>
                        <span>${note}</span>
                    </div>
                `).join('');
            }
        }
        else if (fileInfo.lnk_info) {
            // Show LNK-specific information section
            const lnkInfoSection = document.getElementById('lnkInfo') || createLnkInfoSection();
            lnkInfoSection.classList.remove('hidden');
            renderLnkInfo(fileInfo.lnk_info);
        }
    }

    function getRuntimeConfig(buildWith) {
        const configs = {
            'go': {
                title: 'API Imports Analysis (Go Runtime)',
                badge: 'Go Runtime',
                badgeLabel: 'Go Runtime',
                countClass: 'bg-blue-500/10 text-blue-400',
                dllColor: 'text-blue-400',
                categoryBg: 'bg-blue-500/20',
                categoryText: 'text-blue-400',
                badgeBg: 'bg-gray-500/20',
                badgeText: 'text-gray-400',
                iconColor: 'text-blue-500',
                checksumClass: 'bg-blue-500/10 text-blue-400',
                checksumNote: 'Go binaries typically have non-standard PE checksums - This is normal behavior'
            },
            'rust': {
                title: 'API Imports Analysis (Rust Runtime)',
                badge: 'Rust Runtime',
                badgeLabel: 'Rust Runtime',
                countClass: 'bg-purple-500/10 text-purple-400',
                dllColor: 'text-purple-400',
                categoryBg: 'bg-purple-500/20',
                categoryText: 'text-purple-400',
                badgeBg: 'bg-gray-500/20',
                badgeText: 'text-gray-400',
                iconColor: 'text-purple-500',
                checksumClass: 'bg-purple-500/10 text-purple-400',
                checksumNote: 'Rust binaries may have non-standard PE checksums - This is normal behavior'
            }
        };
        
        const defaultConfig = {
            title: 'Suspicious Imports Analysis',
            badge: null,
            badgeLabel: 'Suspicious',
            countClass: 'bg-red-500/10 text-red-500',
            dllColor: 'text-red-500',
            categoryBg: 'bg-red-500/20',
            categoryText: 'text-red-400',
            badgeBg: 'bg-red-500/20',
            badgeText: 'text-red-400',
            iconColor: 'text-yellow-500',
            checksumClass: 'bg-red-500/10 text-red-500',
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
                                <span class="px-2 py-1 text-sm ${isStandardSection ? 'bg-gray-900/50 text-gray-400' : 'bg-red-500/10 text-red-500'} rounded-lg border ${isStandardSection ? 'border-gray-800' : 'border-red-900/20'}">
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
                summaryText = `Go binary detected: ${runtimeCount} Go runtime imports (benign) and ${suspiciousCount} potentially suspicious imports found.`;
            } else {
                summaryText = `Go binary detected: ${runtimeCount} Go runtime imports found - these are typically benign.`;
            }
        } else if (buildWith === 'rust') {
            if (suspiciousCount > 0) {
                summaryText = `Rust binary detected: ${runtimeCount} Rust runtime imports (benign) and ${suspiciousCount} potentially suspicious imports found.`;
            } else {
                summaryText = `Rust binary detected: ${runtimeCount} Rust runtime imports found - these are typically benign.`;
            }
        } else {
            const totalImports = runtimeCount + suspiciousCount;
            summaryText = `Found ${totalImports} potentially suspicious imports that may indicate malicious capabilities.`;
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
        const allowedExtensions = Array.from(document.querySelectorAll('#dropZone .font-mono'))
            .map(el => el.textContent.trim().substring(1));

        if (!allowedExtensions.includes(extension)) {
            showToast(`Unsupported file type. Allowed types: ${allowedExtensions.join(', ')}`, 'error');
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
                            window.location.href = `/results/${currentFileHash}/byovd`;
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
                
            } else if (type === 'dynamic') {
                // Get user-specified arguments for dynamic analysis
                const argsInput = document.getElementById('analysisArgs').value;
                const args = argsInput.split(' ').filter(arg => arg.trim() !== '');
                
                // Save arguments to localStorage
                localStorage.setItem('analysisArgs', JSON.stringify(args));
                
                // Navigate to dynamic analysis
                window.location.href = `/analyze/${type}/${currentFileHash}`;
            } else {
                // Navigate to static analysis
                window.location.href = `/analyze/${type}/${currentFileHash}`;
            }
        }, UPLOAD_CONFIG.transitionDelay);
    };

    // Monitor dynamic analysis options visibility to show/hide args input
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'attributes' && mutation.attributeName === 'class') {
                const target = mutation.target;
                if (target.id === 'regularAnalysisOptions') {
                    // Show args input only when regular analysis options are visible
                    if (target.classList.contains('hidden')) {
                        elements.argsInputContainer.classList.add('hidden');
                    } else {
                        elements.argsInputContainer.classList.remove('hidden');
                    }
                }
            }
        });
    });
    
    // Observe changes to analysis options
    if (elements.regularAnalysisOptions) {
        observer.observe(elements.regularAnalysisOptions, { attributes: true });
    }
});