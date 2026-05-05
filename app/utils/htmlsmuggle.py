# app/utils/htmlsmuggle.py
"""HTML-smuggling pattern scanner.

Runs at upload time on `.html` / `.htm` files (alongside `get_pe_info`,
`get_office_info`, `get_lnk_info`). Output lands in `file_info.html_smuggle_info`
and is rendered on the upload-result page the same way office_info is.

Pattern set + scoring model ported from SmuggleShield's `content.js`
(https://github.com/RootUp/SmuggleShield). The browser extension catches
runtime behaviour (DOM mutation, blob URL revoke, programmatic <a download>
click); we catch the file-on-disk equivalent by regex-scanning the raw
HTML source.

Scoring (mirrors SmuggleShield):
  - Each pattern carries a weight (2-4).
  - High-weight (>=3) patterns scanned first; early-return when the score
    crosses the threshold.
  - Low-weight (<3) patterns scanned only when high-weight pass landed
    within `threshold - 2` of crossing.
  - A cheap pre-filter (`atob | blob | base64 | createobjecturl | ...`)
    skips files that obviously aren't smuggling.
"""

import os
import re
from typing import Dict, List


# (weight, pattern, name, category)
_PATTERNS = [
    # --- Direct base64 -> binary -> blob path ----------------------------
    (3, r'atob\s*\([^)]+\).*new\s+uint8array',                                                              'atob_to_uint8array',           'encoding'),
    (3, r"atob\s*\(\s*['\"]([A-Za-z0-9+/=]{100,})['\"].*\)",                                                'large_base64_atob',            'encoding'),
    (3, r'new\s+blob\s*\(\s*\[\s*(?:data|atob\s*\()',                                                       'blob_from_atob_data',          'blob'),
    (4, r"let\s+arrayBuffer\s*=\s*\['0x[0-9a-f]{2}'(?:\s*,\s*'0x[0-9a-f]{2}')+\]",                          'hex_array_buffer',             'encoding'),

    # --- Reversed-string fromCharCode obfuscation ------------------------
    (4, r'\["edoCrahCmorf"(?:\s*\[\s*"split"\s*\]\s*\(\s*""\s*\)\s*\[\s*"reverse"\s*\]\s*\(\s*\)\s*\[\s*"join"\s*\]\s*\(\s*""\s*\))', 'reversed_fromcharcode_obf', 'obfuscation'),
    (4, r'setTimeout\s*\(\s*\[.*?\]\.map\s*\(\s*.*?=>.*?(?:fromCharCode|edoCrahCmorf).*?\/\s*\d+\s*\)',     'settimeout_fromcharcode',      'obfuscation'),
    (3, r'String\s*\[\s*(?:"edoCrahCmorf"|[\'"][^\'\"]+[\'"]\.split\([\'"][\'"]\)\.reverse\(\)\.join\([\'"][\'"]\))\s*\]', 'string_reverse_index', 'obfuscation'),

    # --- Blob -> object URL -> download chain ----------------------------
    (3, r'url\.createobjecturl\s*\(\s*(?:my)?blob\s*\)',                                                    'createobjecturl_from_blob',    'blob'),
    (3, r'location(?:\s*\[\s*[\'"]href[\'"]\s*\])?\s*=\s*url',                                              'location_href_assign',         'writer'),
    (2, r'url\.revokeobjecturl\s*\(\s*url\s*\)',                                                            'revokeobjecturl',              'blob'),
    (3, r'\.style\s*=\s*[\'"]display:\s*none[\'"].*\.href\s*=.*\.download\s*=',                             'hidden_anchor_download',       'writer'),
    (3, r'\.click\s*\(\s*\).*url\.revokeobjecturl',                                                         'auto_click_then_revoke',       'writer'),
    (3, r'href\s*=\s*["\']data:(?:application/octet-stream|image/svg\+xml);base64,',                        'data_url_octet_stream',        'writer'),

    # --- Bracket-string property access (window["a"+"to"+"b"] etc.) ------
    (3, r'window\s*\[\s*(?:["\']\w+["\']\s*\+\s*)+["\']\w+["\']\s*\]',                                      'window_bracket_concat',        'obfuscation'),
    (4, r'document\s*\[\s*(?:["\']\w+["\']\s*\+\s*)+["\']\w+["\']\s*\]\s*\(\s*window\s*\[\s*(?:[\'"]at[\'"].*[\'"]o[\'"].*[\'"]b[\'"]\s*\]|\s*(?:["\']\w+["\']\s*\+\s*)+["\']\w+["\']\s*\])\s*\([\'"][A-Za-z0-9+/=]+[\'"]\)\s*\)', 'document_bracket_atob', 'obfuscation'),
    (4, r'var\s+\w+=\w+;?\s*\(function\(\w+,\w+\)\{.*while\(!!\[\]\)\{try\{.*parseint.*\}catch\(\w+\)\{.*\}\}\(.*\)\);?', 'parseint_obfuscator',    'obfuscation'),

    # --- Blob mime-type signatures + writer chain ------------------------
    (3, r'blob\s*\(\s*\[[^\]]+\]\s*,\s*\{\s*type\s*:\s*[\'"](?:application/octet-stream|text/html|octet/stream)[\'"](?:\s*,\s*encoding\s*:\s*[\'"]base64[\'"])?\s*\}\s*\)', 'blob_with_octet_type', 'blob'),

    # --- WebAssembly / Go runtime smuggling ------------------------------
    (3, r'webassembly\s*\.\s*(?:instantiate(?:streaming)?|instance)',                                       'webassembly_instantiate',      'wasm'),
    (2, r'navigator\.serviceworker\.register',                                                              'service_worker_register',      'wasm'),
    (2, r'wasm[_-]?exec\.js',                                                                               'wasm_exec_js',                 'wasm'),
    (3, r'\.wasm\b',                                                                                        'wasm_extension_ref',           'wasm'),
    (3, r'new\s+go\s*\(\s*\)',                                                                              'go_runtime_new',               'wasm'),
    (3, r'go\s*\.\s*run\s*\(',                                                                              'go_runtime_run',               'wasm'),

    # --- Embedded srcdoc / iframe + script -------------------------------
    (3, r'srcdoc\s*=\s*["\'][^"\']*<script',                                                                'srcdoc_with_script',           'writer'),
    (3, r'<embed[^>]*base64',                                                                               'embed_with_base64',            'writer'),

    # --- Decoder helpers + legacy IE save -------------------------------
    (3, r'function\s+(?:b64toarray|xor|base64toarraybuffer)\s*\([^)]*\)\s*\{[\s\S]*?return\s+(?:bytes\.buffer|result);?\}', 'decoder_helper_func', 'encoding'),
    (3, r'document\.createelement\([\'"]embed[\'"]\)',                                                      'createelement_embed',          'writer'),
    (2, r'\.setattribute\([\'"]src[\'"]\s*,\s*.*\)',                                                        'setattribute_src',             'writer'),
    (3, r'window\.navigator\.mssaveoropenblob\s*\(\s*blob\s*,\s*filename\s*\)',                             'mssaveoropenblob',             'writer'),
    (2, r'(?:window\.)?url\.createobjecturl\s*\(\s*(?:blob|[^)]+)\s*\)',                                    'generic_createobjecturl',      'blob'),
    (2, r'(?:a|element)\.download\s*=\s*(?:filename|[\'"][^\'"]+[\'"])',                                    'anchor_download_attr',         'writer'),
    (2, r'string\.fromcharcode\(.*\)',                                                                      'string_fromcharcode',          'encoding'),
    (2, r'\.charcodeat\(.*\)',                                                                              'charcodeat',                   'encoding'),
    (3, r'document\.getelementbyid\([\'"]passwordid[\'"]\)\.value',                                         'password_field_lookup',        'writer'),
    (3, r'import\s*\(\s*url\.createobjecturl\s*\(',                                                         'dynamic_import_objurl',        'wasm'),
    (3, r'\w+\s*\(\s*\w+\s*\(\s*[\'"][A-Za-z0-9+/=]{50,}[\'"]\s*\)\s*\)',                                   'nested_call_long_b64',         'encoding'),
    (2, r'(?:window\.)?atob\s*\(',                                                                          'atob_call',                    'encoding'),
    (2, r'uint8[aA]rray\s*\(\s*(?:(?!len)[^)])*\)',                                                         'uint8array_constructor',       'encoding'),
    (3, r'mssaveoropenblob|mssaveblob',                                                                     'mssave_alias',                 'writer'),
    (3, r'base64toarraybuffer',                                                                             'b64_to_arraybuffer_helper',    'encoding'),
    (3, r'xmlhttprequest\(\).*\.responsetype\s*=\s*[\'"]arraybuffer[\'"]',                                  'xhr_arraybuffer_response',     'encoding'),
    (3, r'new\s+dataview\(.*\).*\.getuint8\(.*\).*\.setuint8\(',                                            'dataview_getset_uint8',        'encoding'),
    (2, r'[^\w](\w+)\s*=\s*(\w+)\s*\^\s*(\w+)',                                                             'xor_operation',                'encoding'),
    (2, r'\.slice\(\s*\w+\s*-\s*\d+\s*,\s*\w+\s*-\s*\d+\s*\)',                                              'string_slice_offset',          'obfuscation'),
    (3, r'for\s*\([^)]+\)\s*\{[^}]*string\.fromcharcode\([^)]+\)',                                          'loop_fromcharcode',            'encoding'),

    # --- GWT (Google Web Toolkit) smuggling artefacts --------------------
    (4, r'\$wnd\s*=\s*window;\s*\$doc\s*=\s*\$wnd\.document',                                               'gwt_wnd_doc',                  'gwt'),
    (4, r'__gwt_(?:isKnownPropertyValue|getMetaProperty|marker|stylesLoaded|scriptsLoaded)',                'gwt_internals',                'gwt'),
    (3, r'\$strongName\s*=\s*[\'"][0-9A-F]{32}[\'"]',                                                       'gwt_strong_name',              'gwt'),
    (3, r'\$gwt_version\s*=\s*[\'"][0-9.]+[\'"]',                                                           'gwt_version',                  'gwt'),
    (4, r'(?:function|var)\s+[a-zA-Z$_]+\s*=\s*\{\s*[a-zA-Z$_]+:\s*window,\s*[a-zA-Z$_]+:\s*document\s*\}', 'gwt_window_doc_pair',          'gwt'),
    (3, r'\b(?:gwtOnLoad|__gwtStatsEvent|gwtOnLoadFunc)\b',                                                 'gwt_onload',                   'gwt'),
    (3, r'\.setAttribute\([\'"]__gwt_property[\'"]',                                                        'gwt_property_attr',            'gwt'),
    (4, r'document\.createElement\([\'"]script[\'"]\).*?\.src\s*=.*?\.cache\.js',                           'gwt_cache_js',                 'gwt'),

    # --- Mouse/event-triggered drop chains -------------------------------
    (4, r'(?:document|window)\.on(?:mousemove|load|mouseover)\s*=\s*function\s*\(\s*\)\s*\{[^}]*?data:application/[^}]*?\.click\(\)[^}]*?(?:removeChild|remove)\(', 'mouse_event_drop', 'writer'),
    (4, r'(?:window|var|let)\.\w+Triggered\s*=\s*(?:true|false).*?(?:navigator|platform).*?data:application/[^;]+;base64,.*?\.(?:download|click)', 'triggered_flag_drop', 'writer'),
    (4, r'navigator\[?["\']platform["\']\]?.*?(?:document|window)\.on\w+.*?data:application/',              'platform_event_drop',          'writer'),

    # --- Generic split/concat/reverse obfuscation ------------------------
    (3, r'\[[\'"][^\'\"]+[\'"]\s*\+\s*[\'"][^\'\"]+[\'"]\]',                                                'string_concat_index',          'obfuscation'),
    (3, r"\[\'[a-z]+\'\s*\+\s*\'[a-z]+\'\]",                                                                'concat_lower_index',           'obfuscation'),
    (3, r"\[\s*(?:[\'\"]\w?[\'\"](?:\s*,\s*)?){4,}\s*\]\.join\s*\(\s*[\'\"]*\s*\)",                         'array_join_join',              'obfuscation'),
    (3, r'const\s+\w+\s*=\s*\[\s*(?:[\'"]\w?[\'"](?:\s*,\s*)?){4,}',                                        'const_char_array',             'obfuscation'),
    (4, r'(\[(?:\][^(]*|\[\])[^(]*|\w+\.)constructor\s*\(\s*([\'"])return\s*\w+\2\s*\)',                    'constructor_return',           'obfuscation'),
    (4, r'Function\s*\(\s*[\'"]return\s+\w+[\'"](?:\s*\)\s*\(\s*\)|\(\))',                                  'function_return',              'obfuscation'),
    (3, r'\w+\.split\s*\(\s*[\'"][\'\"]?\s*\)\.reverse\s*\(\s*\)\.join\s*\(',                               'split_reverse_join',           'obfuscation'),
    (3, r'\[\s*\w+\.split\s*\(\s*[\'"][\'"]\s*\)\.reverse\s*\(\s*\)',                                       'array_split_reverse',          'obfuscation'),
    (3, r'setTimeout\s*\(\s*(?:function|\(\)|[^,]+)\s*(?:=>)?\s*\{[\s\S]{10,}?setTimeout\s*\(',             'nested_settimeout',            'obfuscation'),
    (4, r'setTimeout\s*\([^{)]*\{[^{}]*setTimeout\s*\([^{)]*\{[^{}]*\}',                                    'double_settimeout',            'obfuscation'),
    (4, r'new\s*\([^)]*\[\s*(?:[\'"][^\'\"]+[\'"]\.split|[\'"]\w+[\'"]\.split)',                            'new_with_split_index',         'obfuscation'),
    (3, r'\[[^\]]*(?:join|reverse)[^\]]*\]\s*\(\s*(?:\w+|[\'"][^\'"]*[\'"])\s*\)',                          'index_join_reverse',           'obfuscation'),
    (3, r'\[\s*(?:urlMethod|parts\.join\(\)|[\'"]\w+[\'"]\s*\+)',                                           'partsjoin_index',              'obfuscation'),
    (4, r'\w+\s*\[\s*(?:[\'"][^\'\"]+[\'"](?:\s*\+\s*)?)+\s*\]\s*\(\s*\w+\s*\)',                            'concat_call',                  'obfuscation'),

    # --- "down" + "load" decomposition (extremely common) ----------------
    (3, r'[\'"]?down[\'"]?\s*\+\s*[\'"]?load[\'"]?',                                                        'down_plus_load',               'obfuscation'),
    (4, r"\['down' \+ 'load'\]",                                                                            'down_load_bracket_exact',      'obfuscation'),
    (4, r'createElement\s*\(\s*[\'"]a[\'"]\s*\)[^}]*?\[\s*[\'"]\w+[\'"]\s*\+\s*[\'"]\w+[\'"]\s*\]',         'createanchor_concat_attr',     'writer'),
    (3, r"\['style'\]\['visi' \+ 'bility'\]",                                                               'visibility_concat',            'obfuscation'),

    # --- Chunked-substr + dataset-based payload chains -------------------
    (3, r'function\s+\w+Chunks\s*\([^)]*\)\s*\{[^{}]*for\s*\([^{}]*\)\s*\{[^{}]*substr',                    'chunk_substr_loop',            'encoding'),
    (2, r'\.substr\s*\(\s*\w+\s*,\s*\w+Size\s*\)',                                                          'substr_size_param',            'encoding'),
    (4, r'\(async\s*\(\s*\)\s*=>\s*\{\s*(?:let|var|const)\s+d\s*=.*?(?:document\.getElementById|document\.querySelector).*?dataset.*?\.href\s*=\s*d.*?\.download\s*=.*?\.click\s*\(\s*\)', 'async_dataset_click', 'writer'),
    (4, r'\bdocument\.getElementById\s*\(\s*[\'"]data[\'"]\s*\).*?\.dataset\.file.*?createElement\s*\(\s*[\'"]a[\'"]\s*\).*?\.download\s*=', 'data_div_dataset_anchor', 'writer'),
    (3, r'<div[^>]*id\s*=\s*["\']data["\'][^>]*data-file\s*=\s*["\'][A-Za-z0-9+/=]{50,}["\'][^>]*>',        'data_div_with_b64',            'writer'),
    (4, r'<script>\s*\(\s*async\s*\(\s*\)\s*=>\s*\{[^}]*createElement\s*\(\s*[\'"]a[\'"]\s*\)[^}]*\.click\s*\(\s*\)[^}]*\.remove\s*\(\s*\)', 'inline_async_click_remove', 'writer'),
    (4, r'\b(?:atob|decodeURIComponent)\s*\([^)]*(?:dataset|getAttribute)\s*\.[^)]*\)[^;]*\.href\s*=[^;]*\.download\s*=[^;]*\.click\s*\(\s*\)', 'decode_dataset_click', 'writer'),
    (4, r'\bdocument\.body\.appendChild\s*\([^)]+\)[^;]*\.click\s*\(\s*\)[^;]*\.remove\s*\(\s*\)',          'append_click_remove',          'writer'),
]

# Quick-reject filter -- skip the full regex pass on obviously-clean HTML.
_QUICK_CHECK = re.compile(
    r'blob|atob|download|base64|arraybuffer|uint8array|createobjecturl|fromcharcode',
    re.IGNORECASE,
)
_THRESHOLD = 4
_MAX_BYTES = 5 * 1024 * 1024   # 5 MiB cap on what we read for the scan

# Pre-compile patterns once at import time.
_RE_FLAGS = re.IGNORECASE | re.DOTALL
_COMPILED = [(w, re.compile(p, _RE_FLAGS), n, c) for w, p, n, c in _PATTERNS]
_HIGH = [t for t in _COMPILED if t[0] >= 3]
_LOW  = [t for t in _COMPILED if t[0] < 3]


def get_html_smuggle_info(filepath: str) -> Dict:
    """Public entry. Returns `{html_smuggle_info: {...}}` or `{html_smuggle_info: None}`
    on read error -- mirrors `get_office_info` / `get_lnk_info` shape so file_io can
    do `file_info.update(result)` without conditionals."""
    try:
        size = os.path.getsize(filepath)
        with open(filepath, 'rb') as f:
            raw = f.read(_MAX_BYTES)
        content = raw.decode('utf-8', errors='replace')
        truncated = size > len(raw)
    except OSError as e:
        return {'html_smuggle_info': {'error': f'read failed: {e}'}}

    features = _features(content)
    iocs = _iocs(content)

    if not _QUICK_CHECK.search(content):
        return {'html_smuggle_info': _build(False, 0, [], features, iocs, truncated)}

    score, matches = _scan(content, _HIGH, _THRESHOLD)
    if score < _THRESHOLD and score >= max(0, _THRESHOLD - 2):
        extra_score, extra_matches = _scan(content, _LOW, _THRESHOLD - score)
        score += extra_score
        matches += extra_matches

    return {'html_smuggle_info': _build(score >= _THRESHOLD, score, matches, features, iocs, truncated)}


def _scan(content: str, patterns, max_score: int):
    score = 0
    matches: List[Dict] = []
    for weight, rx, name, category in patterns:
        if rx.search(content):
            score += weight
            matches.append({'name': name, 'category': category, 'weight': weight})
            if score >= max_score:
                break
    return score, matches


def _features(content: str) -> Dict:
    """Surface-level counts -- mirror SmuggleShield's MLDetector feature set."""
    base64_lengths = [
        len(m.group(0))
        for m in re.finditer(r'[A-Za-z0-9+/=]{50,}', content)
    ]
    return {
        'file_size': len(content),
        'has_blob': bool(re.search(r'\bblob\s*\(', content, re.IGNORECASE)),
        'has_atob': bool(re.search(r'\batob\s*\(', content, re.IGNORECASE)),
        'has_uint8array': bool(re.search(r'\buint8array\b', content, re.IGNORECASE)),
        'has_createobjecturl': bool(re.search(r'createobjecturl', content, re.IGNORECASE)),
        'has_download_attr': bool(re.search(r'\bdownload\s*=\s*[\'"][^\'"]+[\'"]', content, re.IGNORECASE)),
        'has_fromcharcode': bool(re.search(r'fromcharcode', content, re.IGNORECASE)),
        'script_tags': len(re.findall(r'<script\b', content, re.IGNORECASE)),
        'iframe_tags': len(re.findall(r'<iframe\b', content, re.IGNORECASE)),
        'embed_tags': len(re.findall(r'<embed\b', content, re.IGNORECASE)),
        'base64_blob_count': len(base64_lengths),
        'largest_base64_chars': max(base64_lengths) if base64_lengths else 0,
    }


def _iocs(content: str) -> Dict:
    """Pull operator-readable artifacts -- attempted download filenames,
    the largest embedded base64 blob, dataset-based payload tags."""
    download_names = list({
        m.group(1)
        for m in re.finditer(r'\bdownload\s*=\s*[\'"]([^\'"]{1,100})[\'"]', content, re.IGNORECASE)
    })[:20]

    largest_b64 = ''
    for m in re.finditer(r'[A-Za-z0-9+/=]{200,}', content):
        blob = m.group(0)
        if len(blob) > len(largest_b64):
            largest_b64 = blob
            if len(largest_b64) > 50000:
                break

    data_file_attrs = list({
        m.group(1)[:200]
        for m in re.finditer(r'\bdata-file\s*=\s*[\'"]([A-Za-z0-9+/=]{20,})[\'"]', content, re.IGNORECASE)
    })[:10]

    return {
        'download_filenames': download_names,
        'data_file_attrs': data_file_attrs,
        'largest_base64_blob': {
            'length': len(largest_b64),
            'preview_first_120': largest_b64[:120],
            'preview_last_120': largest_b64[-120:] if len(largest_b64) > 120 else '',
        } if largest_b64 else None,
    }


def _build(is_smuggling: bool, score: int, matches, features, iocs, truncated: bool) -> Dict:
    by_category: Dict[str, int] = {}
    for m in matches:
        by_category[m['category']] = by_category.get(m['category'], 0) + 1

    notes: List[str] = []
    if is_smuggling:
        notes.append(
            f"HTML smuggling detected -- pattern score {score} >= threshold {_THRESHOLD} "
            f"({len(matches)} pattern{'s' if len(matches) != 1 else ''} fired)"
        )
    elif score > 0:
        notes.append(f"Suspicious patterns present but below threshold ({score}/{_THRESHOLD})")
    if features.get('largest_base64_chars', 0) >= 1000:
        notes.append(
            f"Large base64 blob present ({features['largest_base64_chars']} chars) "
            f"-- typical of smuggled binary payload"
        )
    if features.get('has_download_attr') and features.get('has_blob'):
        notes.append("Combination of <a download> + Blob -- classic smuggling-writer chain")
    if features.get('has_atob') and features.get('has_uint8array'):
        notes.append("atob() + Uint8Array decode chain present")

    return {
        'is_smuggling': is_smuggling,
        'score': score,
        'threshold': _THRESHOLD,
        'matched_patterns': matches,
        'matched_categories': by_category,
        'features': features,
        'iocs': iocs,
        'truncated': truncated,
        'detection_notes': notes,
    }
