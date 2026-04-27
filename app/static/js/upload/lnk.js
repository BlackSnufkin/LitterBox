// app/static/js/upload/lnk.js
// Pure renderers for the LNK preview block in the upload page.
// Called by core.js when the uploaded file is detected as a Windows shortcut.

export function createLnkInfoSection() {
    // Create LNK info section if it doesn't exist
    const lnkInfoSection = document.createElement('div');
    lnkInfoSection.id = 'lnkInfo';
    lnkInfoSection.className = 'bg-gray-900/30 rounded-lg p-4 hidden';
    
    // Insert after office info section
    const officeInfo = document.getElementById('officeInfo');
    officeInfo.parentNode.insertBefore(lnkInfoSection, officeInfo.nextSibling);
    
    return lnkInfoSection;
}

export function renderLnkInfo(lnkInfo) {
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

export function calculateLnkRisk(targetCommand) {
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

export function getRiskLevelClass(riskLevel) {
    const classes = {
        'Critical': 'bg-red-500/20 text-red-400 border border-red-900/20',
        'High': 'bg-orange-500/20 text-orange-400 border border-orange-900/20',
        'Medium': 'bg-yellow-500/20 text-yellow-400 border border-yellow-900/20',
        'Low': 'bg-green-500/20 text-green-400 border border-green-900/20'
    };
    return classes[riskLevel] || classes['Low'];
}

export function getTargetCommandBorderClass(riskLevel) {
    const classes = {
        'Critical': 'border-red-500',
        'High': 'border-orange-500',
        'Medium': 'border-yellow-500',
        'Low': 'border-green-500'
    };
    return classes[riskLevel] || classes['Low'];
}

export function getTargetCommandTextClass(riskLevel) {
    const classes = {
        'Critical': 'text-red-400',
        'High': 'text-orange-400',
        'Medium': 'text-yellow-400',
        'Low': 'text-green-400'
    };
    return classes[riskLevel] || classes['Low'];
}

