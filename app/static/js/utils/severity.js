// app/static/js/utils/severity.js
// Single source of truth for severity-to-style mapping. Consolidates the
// scattered definitions in results.js, blender.js, holygrail.js.

export const SeverityMap = {
    CRITICAL: { color: 'text-red-500',    bg: 'bg-red-500/10',    border: 'border-red-500/20'    },
    HIGH:     { color: 'text-orange-500', bg: 'bg-orange-500/10', border: 'border-orange-500/20' },
    MEDIUM:   { color: 'text-yellow-500', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20' },
    MID:      { color: 'text-yellow-500', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20' },
    LOW:      { color: 'text-blue-500',   bg: 'bg-blue-500/10',   border: 'border-blue-500/20'   },
    INFO:     { color: 'text-gray-400',   bg: 'bg-gray-500/10',   border: 'border-gray-500/20'   },
};

const NUMERIC_SEVERITY = { 100: 'CRITICAL', 80: 'HIGH', 50: 'MEDIUM', 20: 'LOW', 5: 'INFO' };

// Normalise any severity value (string, number, mixed-case) into a key.
export function normalizeSeverity(value) {
    if (value === null || value === undefined) return 'LOW';
    if (typeof value === 'number') return NUMERIC_SEVERITY[value] || 'LOW';
    return String(value).toUpperCase();
}

// Convenience: get all classes for a severity level.
export function severityClasses(value) {
    const key = normalizeSeverity(value);
    return SeverityMap[key] || SeverityMap.LOW;
}
