// app/static/js/summery.js

const elements = {
    // File (payload) elements
    fileList: document.getElementById('fileList'),
    fileRowTemplate: document.getElementById('fileRowTemplate'),
    emptyState: document.getElementById('emptyState'),
    searchFiles: document.getElementById('searchFiles'),
    filterType: document.getElementById('filterType'),
    filterRisk: document.getElementById('filterRisk'),
    sortBy: document.getElementById('sortBy'),
    totalFiles: document.getElementById('totalFiles'),
    storageUsed: document.getElementById('storageUsed'),
    averageRisk: document.getElementById('averageRisk'),
    averageEntropy: document.getElementById('averageEntropy'),
    
    // Driver elements
    driverList: document.getElementById('driverList'),
    driverRowTemplate: document.getElementById('driverRowTemplate'),
    driverEmptyState: document.getElementById('driverEmptyState'),
    totalDrivers: document.getElementById('totalDrivers'),
    driverStorageUsed: document.getElementById('driverStorageUsed'),
    driverAverageRisk: document.getElementById('driverAverageRisk'),
    
    // Process elements
    processList: document.getElementById('processList'),
    processRowTemplate: document.getElementById('processRowTemplate'),
    processEmptyState: document.getElementById('processEmptyState'),
    totalProcesses: document.getElementById('totalProcesses'),
    highRiskProcesses: document.getElementById('highRiskProcesses'),
    processAverageRisk: document.getElementById('processAverageRisk')
};

let files = [];
let drivers = [];
let processes = [];

async function loadFiles() {
    try {
        const response = await fetch('/files');
        const data = await response.json();
        
        if (data.status === 'success') {
            // Handle payload-based analyses (files)
            if (data.payload_based && data.payload_based.payloads) {
                files = Object.entries(data.payload_based.payloads).map(([md5, file]) => ({
                    md5,
                    ...file
                }));
                updateStats();
                renderFiles();
            }
            
            // Handle driver-based analyses
            if (data.driver_based && data.driver_based.drivers) {
                drivers = Object.entries(data.driver_based.drivers).map(([md5, driver]) => ({
                    md5,
                    ...driver
                }));
                updateDriverStats();
                renderDrivers();
            }
            
            // Handle process-based analyses
            if (data.pid_based && data.pid_based.processes) {
                processes = Object.entries(data.pid_based.processes).map(([pid, process]) => ({
                    pid,
                    ...process
                }));
                updateProcessStats();
                renderProcesses();
            }
        }
    } catch (error) {
        console.error('Error loading data:', error);
    }
}

// File (payload) functions
function updateStats() {
    elements.totalFiles.textContent = files.length;
    
    const totalBytes = files.reduce((sum, file) => sum + (file.file_size || 0), 0);
    elements.storageUsed.textContent = formatFileSize(totalBytes);
    
    const filesWithRisk = files.filter(f => f.risk_assessment && f.risk_assessment.score !== undefined);
    
    if (filesWithRisk.length > 0) {
        const avgRiskScore = filesWithRisk.reduce((sum, file) => 
            sum + file.risk_assessment.score, 0) / filesWithRisk.length;
        
        let riskText, riskClass;
        
        if (avgRiskScore >= 75) {
            riskText = 'Critical';
            riskClass = 'bg-red-500/15 text-red-300 border border-red-500/30';
        } else if (avgRiskScore >= 50) {
            riskText = 'High';
            riskClass = 'bg-orange-500/15 text-orange-300 border border-orange-500/30';
        } else if (avgRiskScore >= 25) {
            riskText = 'Medium';
            riskClass = 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30';
        } else {
            riskText = 'Low';
            riskClass = 'bg-green-500/15 text-green-300 border border-green-500/30';
        }

        elements.averageRisk.textContent = `${riskText} Detection`;
        elements.averageRisk.className = 'px-2 py-1 text-sm rounded-lg inline-flex items-center justify-center font-medium ' + riskClass;
        elements.averageEntropy.textContent = `Detection Score: ${avgRiskScore.toFixed(1)}%`;
    } else {
        elements.averageRisk.textContent = '-';
        elements.averageRisk.className = 'px-2 py-1 text-sm rounded-lg inline-flex items-center justify-center font-medium bg-gray-500/15 text-gray-400 border border-gray-500/30';
        elements.averageEntropy.textContent = 'Detection Score: -';
    }
}

function renderFiles() {
    const filteredFiles = filterFiles(files);
    const sortedFiles = sortFiles(filteredFiles);
    
    elements.fileList.innerHTML = '';
    elements.emptyState.classList.toggle('hidden', sortedFiles.length > 0);
    
    sortedFiles.forEach(file => {
        const row = elements.fileRowTemplate.content.cloneNode(true);
        
        row.querySelector('[data-field="fileName"]').textContent = file.filename;
        row.querySelector('[data-field="fileHash"]').textContent = file.md5;
        
        const riskEl = row.querySelector('[data-field="fileRisk"]');
        const entropyEl = row.querySelector('[data-field="fileEntropy"]');
        
        if (file.risk_assessment) {
            const { level, score, factors } = file.risk_assessment;
            riskEl.textContent = `${level} (${score}%)`;
            // Use the design-system severity tag — the dynamic Tailwind
            // classes weren't getting picked up by the JIT scanner (only
            // template files are scanned, not JS) so `text-orange-300`
            // etc. were missing from the compiled CSS, leaving the badge
            // unstyled white. .lb-tag.<level> is defined globally with
            // the right severity colors from --lb-sev-*.
            riskEl.className = `lb-tag ${(level || 'muted').toLowerCase()}`;

            if (factors && factors.length > 0) {
                entropyEl.textContent = factors[0];
            }
        } else {
            riskEl.textContent = 'Unknown';
            riskEl.className = 'lb-tag muted';
            entropyEl.textContent = '';
        }
        
        row.querySelector('[data-field="fileSize"]').textContent = formatFileSize(file.file_size);
        row.querySelector('[data-field="fileUploadDate"]').textContent = file.upload_time;
        
        const statusCell = row.querySelector('[data-field="fileAnalysisStatus"]');
        const status = getAnalysisStatus(file);
        statusCell.className = '';
        statusCell.innerHTML = renderFileStatusCell(file, status);
        
        const viewButton = row.querySelector('[data-action="view"]');
        const deleteButton = row.querySelector('[data-action="delete"]');
        const reportButton = row.querySelector('[data-action="report"]');
        
        if (reportButton) reportButton.onclick = () => generateFileReport(file.md5);
        viewButton.onclick = () => viewFile(file.md5);
        deleteButton.onclick = () => showFileDeleteWarning(file.md5);
        
        elements.fileList.appendChild(row);
    });
}

// Driver functions
// Driver functions with BYOVD-appropriate colors and terminology
function updateDriverStats() {
    if (!elements.totalDrivers) return;
    
    elements.totalDrivers.textContent = drivers.length;
    
    const totalBytes = drivers.reduce((sum, driver) => sum + (driver.file_size || 0), 0);
    if (elements.driverStorageUsed) {
        elements.driverStorageUsed.textContent = formatFileSize(totalBytes);
    }
    
    const driversWithRisk = drivers.filter(d => d.risk_assessment && d.risk_assessment.score !== undefined);
    
    if (elements.driverAverageRisk && driversWithRisk.length > 0) {
        const avgRiskScore = driversWithRisk.reduce((sum, driver) => 
            sum + driver.risk_assessment.score, 0) / driversWithRisk.length;
        
        let riskText, riskClass;
        // BYOVD perspective: Higher score = Better for exploitation
        if (avgRiskScore >= 75) {
            riskText = 'Excellent';
            riskClass = 'bg-green-500/15 text-green-300 border border-green-500/30';
        } else if (avgRiskScore >= 50) {
            riskText = 'Good';
            riskClass = 'bg-green-500/15 text-green-300 border border-green-500/30';
        } else if (avgRiskScore >= 25) {
            riskText = 'Fair';
            riskClass = 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30';
        } else {
            riskText = 'Poor';
            riskClass = 'bg-red-500/15 text-red-300 border border-red-500/30';
        }

        elements.driverAverageRisk.textContent = `${riskText} BYOVD`;
        elements.driverAverageRisk.className = 'px-2 py-1 text-sm rounded-lg inline-flex items-center justify-center font-medium ' + riskClass;
    } else if (elements.driverAverageRisk) {
        elements.driverAverageRisk.textContent = '-';
        elements.driverAverageRisk.className = 'px-2 py-1 text-sm rounded-lg inline-flex items-center justify-center font-medium bg-gray-500/15 text-gray-400 border border-gray-500/30';
    }
}

function renderDrivers() {
    if (!elements.driverList || !elements.driverEmptyState) return;

    elements.driverList.innerHTML = '';
    elements.driverEmptyState.classList.toggle('hidden', drivers.length > 0);
    
    if (drivers.length === 0) {
        return;
    }

    drivers.forEach(driver => {
        const row = elements.driverRowTemplate.content.cloneNode(true);
        
        row.querySelector('[data-field="driverName"]').textContent = driver.filename;
        row.querySelector('[data-field="driverHash"]').textContent = driver.md5;
        
        const riskEl = row.querySelector('[data-field="driverRisk"]');
        if (driver.risk_assessment) {
            const { level, score } = driver.risk_assessment;
            
            // BYOVD-appropriate terminology and colors
            let byovdLabel, byovdClass;
            const byovdBase = 'px-3 py-1 text-xs rounded-lg inline-flex items-center justify-center font-medium ';
            if (score >= 75) {
                byovdLabel = 'HolyGrail';
                byovdClass = byovdBase + 'bg-green-500/15 text-green-300 border border-green-500/30';
            } else if (score >= 50) {
                byovdLabel = 'Good';
                byovdClass = byovdBase + 'bg-green-500/15 text-green-300 border border-green-500/30';
            } else if (score >= 25) {
                byovdLabel = 'Fair';
                byovdClass = byovdBase + 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30';
            } else {
                byovdLabel = 'Poor';
                byovdClass = byovdBase + 'bg-red-500/15 text-red-300 border border-red-500/30';
            }
            
            riskEl.textContent = `${byovdLabel} (${score}%)`;
            riskEl.className = byovdClass;
        }
        
        row.querySelector('[data-field="driverSize"]').textContent = formatFileSize(driver.file_size);
        row.querySelector('[data-field="driverUploadDate"]').textContent = driver.upload_time;
        
        const statusCell = row.querySelector('[data-field="driverAnalysisStatus"]');
        const status = getDriverAnalysisStatus(driver);
        statusCell.className = `px-2 py-1 text-sm rounded-lg ${status.class}`;
        statusCell.textContent = status.text;
        
        const viewButton = row.querySelector('[data-action="view"]');
        const deleteButton = row.querySelector('[data-action="delete"]');
        const reportButton = row.querySelector('[data-action="report"]');
        
        if (reportButton) reportButton.onclick = () => generateDriverReport(driver.md5);
        if (viewButton) viewButton.onclick = () => viewDriver(driver.md5);
        if (deleteButton) deleteButton.onclick = () => showDriverDeleteWarning(driver.md5);
        
        elements.driverList.appendChild(row);
    });
}

// Process functions
function updateProcessStats() {
    if (!elements.totalProcesses) return;
    
    elements.totalProcesses.textContent = processes.length;
    
    const highRiskCount = processes.filter(p => 
        p.risk_assessment && p.risk_assessment.score >= 75
    ).length;
    
    if (elements.highRiskProcesses) {
        elements.highRiskProcesses.textContent = highRiskCount;
    }
    
    const processesWithRisk = processes.filter(p => 
        p.risk_assessment && p.risk_assessment.score !== undefined
    );
    
    if (elements.processAverageRisk && processesWithRisk.length > 0) {
        const avgRiskScore = processesWithRisk.reduce((sum, process) => 
            sum + process.risk_assessment.score, 0) / processesWithRisk.length;
        
        let riskText, riskClass;
        if (avgRiskScore >= 75) {
            riskText = 'Critical';
            riskClass = 'bg-red-500/15 text-red-300 border border-red-500/30';
        } else if (avgRiskScore >= 50) {
            riskText = 'High';
            riskClass = 'bg-orange-500/15 text-orange-300 border border-orange-500/30';
        } else if (avgRiskScore >= 25) {
            riskText = 'Medium';
            riskClass = 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30';
        } else {
            riskText = 'Low';
            riskClass = 'bg-green-500/15 text-green-300 border border-green-500/30';
        }

        elements.processAverageRisk.textContent = `${riskText} (${avgRiskScore.toFixed(1)}%)`;
        elements.processAverageRisk.className = 'px-2 py-1 text-sm rounded-lg inline-flex items-center justify-center font-medium ' + riskClass;
    }
}

function renderProcesses() {
    if (!elements.processList || !elements.processEmptyState) return;

    elements.processList.innerHTML = '';
    elements.processEmptyState.classList.toggle('hidden', processes.length > 0);
    
    if (processes.length === 0) {
        return;
    }

    processes.forEach(process => {
        const row = elements.processRowTemplate.content.cloneNode(true);
        
        const nameEl = row.querySelector('[data-field="processName"]');
        const pathEl = row.querySelector('[data-field="processPath"]');
        if (nameEl) nameEl.textContent = process.process_name || 'Unknown';
        if (pathEl) pathEl.textContent = process.process_path || '';
        
        const pidEl = row.querySelector('[data-field="pid"]');
        if (pidEl) pidEl.textContent = process.pid;
        
        const riskEl = row.querySelector('[data-field="processRisk"]');
        if (riskEl && process.risk_assessment) {
            const { level, score } = process.risk_assessment;
            riskEl.textContent = `${level} (${score}%)`;
            riskEl.className = 'px-3 py-1 text-xs rounded-lg inline-flex items-center justify-center font-medium';
            
            if (score >= 75) {
                riskEl.className += ' bg-red-500/15 text-red-300 border border-red-500/30';
            } else if (score >= 50) {
                riskEl.className += ' bg-orange-500/15 text-orange-300 border border-orange-500/30';
            } else if (score >= 25) {
                riskEl.className += ' bg-yellow-500/15 text-yellow-300 border border-yellow-500/30';
            } else {
                riskEl.className += ' bg-green-500/15 text-green-300 border border-green-500/30';
            }
        }
        
        const timeEl = row.querySelector('[data-field="processArch"]');
        if (timeEl) timeEl.textContent = process.architecture || 'Unknown';
        
        const viewButton = row.querySelector('[data-action="view"]');
        const deleteButton = row.querySelector('[data-action="delete"]');
        const reportButton = row.querySelector('[data-action="report"]');
        
        if (reportButton) reportButton.onclick = () => generateProcessReport(process.pid);
        if (viewButton) viewButton.onclick = () => viewProcess(process.pid);
        if (deleteButton) deleteButton.onclick = () => showProcessDeleteWarning(process.pid);
        
        elements.processList.appendChild(row);
    });
}

// Filter and sort functions
function filterFiles(files) {
    const searchTerm = elements.searchFiles.value.toLowerCase();
    const fileType = elements.filterType.value;
    const riskLevel = elements.filterRisk.value.toLowerCase();
    
    return files.filter(file => {
        const matchesSearch = file.filename.toLowerCase().includes(searchTerm) ||
                            file.md5.toLowerCase().includes(searchTerm);
        const matchesType = fileType === 'all' || file.filename.toLowerCase().endsWith(fileType);
        const matchesRisk = riskLevel === 'all' || 
                           (file.risk_assessment && file.risk_assessment.level.toLowerCase() === riskLevel);
        return matchesSearch && matchesType && matchesRisk;
    });
}

function sortFiles(files) {
    const sortBy = elements.sortBy.value;
    
    return [...files].sort((a, b) => {
        switch (sortBy) {
            case 'name':
                return a.filename.localeCompare(b.filename);
            case 'newest':
                return new Date(b.upload_time).getTime() - new Date(a.upload_time).getTime();
            case 'oldest':
                return new Date(a.upload_time).getTime() - new Date(b.upload_time).getTime();
            case 'size':
                return (b.file_size || 0) - (a.file_size || 0);
            case 'risk':
                return ((b.risk_assessment?.score || 0) - (a.risk_assessment?.score || 0));
            default:
                return 0;
        }
    });
}

function getAnalysisStatus(file) {
    if (file.has_static_analysis && file.has_dynamic_analysis) {
        return {
            text: 'Complete',
            class: 'bg-green-500/10 text-green-400 border border-green-900/20'
        };
    } else if (file.has_static_analysis || file.has_dynamic_analysis) {
        return {
            text: 'Partial',
            class: 'bg-yellow-500/10 text-yellow-400 border border-yellow-900/20'
        };
    }
    return {
        text: 'No Results',
        class: 'bg-red-500/10 text-red-400 border border-red-900/20'
    };
}

/**
 * Build the Status cell for one file row. Two parts:
 *   - the static-vs-dynamic completion badge (Complete / Partial / No Results)
 *   - an EDR sub-line listing each profile run with alert counts and
 *     block/kill flags. Only rendered when the file has been dispatched
 *     to at least one EDR profile.
 */
function renderFileStatusCell(file, status) {
    const main = `<span class="px-2 py-1 text-sm rounded-lg ${status.class}">${status.text}</span>`;
    if (!file.has_edr_analysis || !Array.isArray(file.edr_runs) || !file.edr_runs.length) {
        return main;
    }
    const badges = file.edr_runs.map(r => {
        const alerts = r.total_alerts || 0;
        const high   = r.high_severity_alerts || 0;
        const blocked = !!r.blocked_by_av;
        const killed  = !!r.killed_by_edr;
        const tone =
            blocked || killed || high > 0 ? 'critical' :
            alerts > 0                   ? 'medium'   :
                                            'info';
        const detail = (
            blocked     ? `${r.display_name}: blocked` :
            killed      ? `${r.display_name}: killed (${alerts})` :
            alerts > 0  ? `${r.display_name}: ${alerts}` :
                          `${r.display_name}: clean`
        );
        return `<span class="lb-tag ${tone}" style="font-size: 10px; margin-right: 4px;">${detail}</span>`;
    }).join('');
    return `${main}<div style="margin-top: 4px; display: flex; flex-wrap: wrap; gap: 2px;">${badges}</div>`;
}

function getDriverAnalysisStatus(driver) {
    if (driver.has_static_analysis) {
        return {
            text: 'Analyzed',
            class: 'bg-green-500/10 text-green-400 border border-green-900/20'
        };
    }
    return {
        text: 'No Results',
        class: 'bg-red-500/10 text-red-400 border border-red-900/20'
    };
}

// Action functions
function viewFile(md5) {
    window.location.href = `/results/info/${md5}`;
}

function viewDriver(md5) {
    window.location.href = `/results/byovd/${md5}`;
}

function viewProcess(pid) {
    window.location.href = `/results/dynamic/${pid}`;
}

function showFileDeleteWarning(md5) {
    const modal = document.getElementById('fileDeleteWarningModal');
    const confirmButton = document.getElementById('confirmDeleteButton');
    confirmButton.onclick = () => deleteFile(md5);
    modal?.classList.remove('hidden');
}

function showDriverDeleteWarning(md5) {
    const modal = document.getElementById('fileDeleteWarningModal');
    const confirmButton = document.getElementById('confirmDeleteButton');
    confirmButton.onclick = () => deleteDriver(md5);
    modal?.classList.remove('hidden');
}

function hideFileDeleteWarning() {
    const modal = document.getElementById('fileDeleteWarningModal');
    modal?.classList.add('hidden');
}

async function deleteFile(md5) {
    try {
        const response = await fetch(`/file/${md5}`, { method: 'DELETE' });
        if (response.ok) {
            hideFileDeleteWarning();
            await new Promise(resolve => setTimeout(resolve, 300));
            files = files.filter(file => file.md5 !== md5);
            updateStats();
            renderFiles();
        }
    } catch (error) {
        console.error('Error deleting file:', error);
    }
}

async function deleteDriver(md5) {
    try {
        const response = await fetch(`/file/${md5}`, { method: 'DELETE' });
        if (response.ok) {
            hideFileDeleteWarning();
            await new Promise(resolve => setTimeout(resolve, 300));
            drivers = drivers.filter(driver => driver.md5 !== md5);
            updateDriverStats();
            renderDrivers();
        }
    } catch (error) {
        console.error('Error deleting driver:', error);
    }
}

async function deleteProcess(pid) {
    try {
        const response = await fetch(`/process/${pid}`, { method: 'DELETE' });
        if (response.ok) {
            processes = processes.filter(process => process.pid !== pid);
            updateProcessStats();
            renderProcesses();
        }
    } catch (error) {
        console.error('Error deleting process:', error);
    }
}

function generateFileReport(md5) {
    window.location.href = `/api/report/${md5}?download=true`;
}

function generateDriverReport(md5) {
    window.location.href = `/api/report/${md5}?download=true`;
}

function generateProcessReport(pid) {
    window.location.href = `/api/report/${pid}?download=true`;
}

function showSummaryCleanupWarning() {
    const modal = document.getElementById('summaryCleanupWarningModal');
    modal?.classList.remove('hidden');
}

function hideSummaryCleanupWarning() {
    const modal = document.getElementById('summaryCleanupWarningModal');
    modal?.classList.add('hidden');
}

async function cleanupFiles() {
    try {
        const response = await fetch('/cleanup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }
        });
        if (response.ok) {
            hideSummaryCleanupWarning();
            await new Promise(resolve => setTimeout(resolve, 300));
            window.location.reload(true);
        }
    } catch (error) {
        console.error('Error cleaning files:', error);
    }
}

function toggleDriverAnalysis() {
    const driverCard = document.getElementById('driverAnalysisCard');
    const toggleButton = event.currentTarget;

    if (driverCard.classList.contains('hidden')) {
        driverCard.classList.remove('hidden');
        toggleButton.querySelector('span').textContent = 'Hide Driver Analysis';
    } else {
        driverCard.classList.add('hidden');
        toggleButton.querySelector('span').textContent = 'Show Driver Analysis';
    }
}

function toggleProcessAnalysis() {
    const processCard = document.getElementById('processAnalysisCard');
    const toggleButton = event.currentTarget;

    if (processCard.classList.contains('hidden')) {
        processCard.classList.remove('hidden');
        toggleButton.querySelector('span').textContent = 'Hide Process Analysis';
    } else {
        processCard.classList.add('hidden');
        toggleButton.querySelector('span').textContent = 'Show Process Analysis';
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Make functions available globally
window.generateFileReport = generateFileReport;
window.generateDriverReport = generateDriverReport;
window.generateProcessReport = generateProcessReport;
window.showSummaryCleanupWarning = showSummaryCleanupWarning;
window.hideSummaryCleanupWarning = hideSummaryCleanupWarning;
window.cleanupFiles = cleanupFiles;
window.showFileDeleteWarning = showFileDeleteWarning;
window.hideFileDeleteWarning = hideFileDeleteWarning;
window.toggleDriverAnalysis = toggleDriverAnalysis;
window.toggleProcessAnalysis = toggleProcessAnalysis;
window.viewProcess = viewProcess;
window.deleteProcess = deleteProcess;

// Event listeners
elements.searchFiles.addEventListener('input', () => renderFiles());
elements.filterType.addEventListener('change', () => renderFiles());
elements.sortBy.addEventListener('change', () => renderFiles());
elements.filterRisk.addEventListener('change', () => renderFiles());

// Initialize
loadFiles();