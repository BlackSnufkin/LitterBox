// app/static/js/results/renderers.js
// Shared UI fragments and small renderers used by tools.js.

import { formatBytes as _formatBytes } from '../utils/formatters.js';
import { escapeHtml } from '../utils/escape.js';
export const formatBytes = _formatBytes;

export const UI = {
    icons: {
        running: `
            <svg class="w-6 h-6 text-red-500 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>`,
        complete: `
            <svg class="w-6 h-6 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
            </svg>`,
        error: `
            <svg class="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>`
    }
};

export function getEventTypeColor(type) {
    const colors = {
        'Process Start': 'bg-green-500',
        'Child Process': 'bg-yellow-500',
        'DLL Load': 'bg-blue-500',
        'Image Load': 'bg-purple-500',
        'Thread Start': 'bg-pink-500'
    };
    return colors[type] || 'bg-gray-500';
}

export function renderSection(title, items) {
    if (!items || items.length === 0) return '';
    
    const displayItems = items.slice(0, 25);
    const remainingCount = items.length - 25;
    
    return `
    <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4">
        <div class="text-sm font-medium text-gray-300 mb-3">
            ${escapeHtml(title)} (${items.length})
        </div>
        <div class="space-y-2">
            ${displayItems.map(item => `
                <div class="text-sm text-gray-400 font-mono break-all bg-gray-900/50 p-2 rounded">
                    ${escapeHtml(item)}
                </div>
            `).join('')}
            ${remainingCount > 0 ? `
                <div class="text-sm text-gray-500 mt-2 p-2">
                    ... and ${remainingCount} more items
                </div>
            ` : ''}
        </div>
    </div>`;
}
