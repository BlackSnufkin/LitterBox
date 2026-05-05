# app/utils/forensics.py
"""PE forensic analysis: entropy, runtime detection, MalAPI lookup.

Office / LNK / HTML-smuggling analyzers live in their own modules
(`utils/office.py`, `utils/lnk.py`, `utils/htmlsmuggle.py`) so each file-type
inspector is self-contained and easy to maintain. This module is now strictly
PE-focused.
"""
import json
import math
from collections import Counter


# Known runtime imports for compiled languages — used to flag PE imports as
# benign-runtime rather than suspicious.
RUNTIME_IMPORTS = {
    'go': {
        'kernel32.dll': {
            'addvectoredexceptionhandler', 'closehandle', 'createeventa',
            'createfilea', 'createiocompletionport', 'createthread',
            'createwaitabletimerexw', 'duplicatehandle', 'exitprocess',
            'freeenvironmentstringsw', 'getconsolemode', 'getenvironmentstringsw',
            'getprocaddress', 'getprocessaffinitymask',
            'getqueuedcompletionstatusex', 'getstdhandle', 'getsystemdirectorya',
            'getsysteminfo', 'getthreadcontext', 'loadlibrarya', 'loadlibraryw',
            'postqueuedcompletionstatus', 'resumethread', 'setconsolectrlhandler',
            'seterrormode', 'setevent', 'setprocesspriorityboost',
            'setthreadcontext', 'setunhandledexceptionfilter', 'setwaitabletimer',
            'suspendthread', 'switchtothread', 'virtualalloc', 'virtualfree',
            'virtualquery', 'waitformultipleobjects', 'waitforsingleobject',
            'writeconsolew', 'writefile',
        }
    },
    'rust': {
        'kernel32.dll': {
            'addvectoredexceptionhandler', 'closehandle', 'createmutexa',
            'formatmessagew', 'getconsolemode', 'getcurrentdirectoryw',
            'getcurrentprocess', 'getcurrentprocessid', 'getcurrentthread',
            'getcurrentthreadid', 'getenvironmentvariablew', 'getlasterror',
            'getmodulehandlea', 'getmodulehandlew', 'getprocaddress',
            'getprocessheap', 'getstdhandle', 'getsystemtimeasfiletime',
            'heapalloc', 'heapfree', 'heaprealloc', 'initializeslisthead',
            'isdebuggerpresent', 'isprocessorfeaturepresent', 'loadlibrarya',
            'multibytetowidechar', 'queryperformancecounter', 'releasemutex',
            'rtlcapturecontext', 'rtllookupfunctionentry', 'rtlvirtualunwind',
            'setlasterror', 'setthreadstackguarantee',
            'setunhandledexceptionfilter', 'unhandledexceptionfilter',
            'waitforsingleobject', 'waitforsingleobjectex', 'widechartomultibyte',
            'writeconsolew', 'lstrlenw',
        },
        'ntdll.dll': {
            'ntwritefile', 'rtlntstatustodoserror',
        }
    }
}


def calculate_entropy(data):
    """Compute Shannon entropy (rounded to 2 decimals) of a byte string.

    Uses `collections.Counter` (C fastpath) instead of a Python loop —
    ~5x faster on multi-MB inputs, which matters for big PE uploads where
    we run this once over the whole file plus once per section.
    """
    n = len(data)
    if n == 0:
        return 0

    if isinstance(data, str):
        data = data.encode()
        n = len(data)

    counts = Counter(data)
    inv_n = 1.0 / n
    entropy = -sum((c * inv_n) * math.log2(c * inv_n) for c in counts.values())
    return round(entropy, 2)


class SecurityAnalyzer:
    """PE import / Office macro analysis with MalAPI database lookup."""

    def __init__(self, malapi_path):
        self.malapi_data = self._load_malapi_data(malapi_path)
        self.dll_function_map = self._build_function_map()

    def _load_malapi_data(self, malapi_path):
        try:
            with open(malapi_path, "r", encoding="utf-8") as f:
                return json.loads(f.read())
        except Exception as e:
            print(f"Error loading MalAPI database: {e}")
            return {}

    def _build_function_map(self):
        dll_function_map = {}

        for category, functions in self.malapi_data.items():
            for function_name, function_info in functions.items():
                if isinstance(function_info, dict):
                    description = function_info.get("description", "")
                    dll_name = function_info.get("dll", "Unknown").lower()
                else:
                    description = function_info
                    dll_name = "unknown"

                if dll_name not in dll_function_map:
                    dll_function_map[dll_name] = {}

                dll_function_map[dll_name][function_name.lower()] = (category, description)

                if "unknown" not in dll_function_map:
                    dll_function_map["unknown"] = {}
                dll_function_map["unknown"][function_name.lower()] = (category, description)

        return dll_function_map

    def _detect_runtime_type(self, pe):
        """Return 'go', 'rust', or None based on PE section content."""
        try:
            rust_indicators = [
                b'rustc', b'rust_begin_unwind', b'rust_panic', b'rust_oom',
                b'__rust_', b'.rustc_info', b'cargo', b'rustup',
            ]

            rust_found = False
            for section in pe.sections:
                try:
                    section_data = section.get_data()
                    for rust_indicator in rust_indicators:
                        if rust_indicator in section_data:
                            rust_found = True
                            break
                    if rust_found:
                        break
                except Exception:
                    continue

            if rust_found:
                return "rust"

            go_sections = ['.go.buildinfo', '.go.plt']
            for section in pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                if section_name in go_sections:
                    return "go"

            high_confidence_indicators = [
                b'go.buildinfo', b'runtime.main', b'runtime.goexit',
                b'runtime.newproc', b'runtime.mallocgc', b'go.string.',
                b'go.func.', b'go.itab.', b'go.mod', b'runtime.systemstack',
                b'go:linkname', b'go:nosplit', b'go:noescape',
                b'runtime.schedt', b'runtime.g', b'runtime.m',
            ]

            go_indicator_count = 0
            for section in pe.sections:
                try:
                    section_data = section.get_data()
                    for indicator in high_confidence_indicators:
                        if indicator in section_data:
                            go_indicator_count += 1
                            if go_indicator_count >= 2:
                                return "go"
                except Exception:
                    continue

            return None

        except Exception:
            return None

    def analyze_pe_imports(self, pe):
        """Return (suspicious_imports, build_with) for a parsed PE."""
        suspicious_imports = []
        build_with = self._detect_runtime_type(pe)

        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return suspicious_imports, build_with

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode().lower()

            for imp in entry.imports:
                if not imp.name:
                    continue

                func_name = imp.name.decode().lower()

                for lookup_dll in [dll_name, "unknown"]:
                    if lookup_dll in self.dll_function_map and func_name in self.dll_function_map[lookup_dll]:
                        category, description = self.dll_function_map[lookup_dll][func_name]

                        hint_value = None
                        if hasattr(imp, 'import_by_ordinal') and imp.import_by_ordinal:
                            hint_value = imp.ordinal if hasattr(imp, 'ordinal') and imp.ordinal is not None else None
                        else:
                            if hasattr(imp, 'hint') and imp.hint is not None:
                                if build_with in ['go', 'rust'] and imp.hint == 0:
                                    hint_value = None
                                else:
                                    hint_value = imp.hint

                        is_runtime_import = False
                        if build_with and build_with in RUNTIME_IMPORTS:
                            runtime_dlls = RUNTIME_IMPORTS[build_with]
                            is_runtime_import = (
                                dll_name in runtime_dlls and
                                func_name in runtime_dlls[dll_name]
                            )

                        suspicious_imports.append({
                            'dll': dll_name,
                            'function': func_name,
                            'category': category,
                            'note': description,
                            'hint': hint_value,
                            'is_runtime_import': is_runtime_import,
                            'runtime_type': build_with if is_runtime_import else None,
                        })
                        break

        return suspicious_imports, build_with

    def analyze_pe_sections(self, pe, entropy_calculator):
        """Build per-section info with entropy and detection notes."""
        sections_info = []
        standard_sections = [
            '.text', '.data', '.bss', '.rdata', '.edata', '.idata',
            '.pdata', '.reloc', '.rsrc', '.tls', '.debug',
        ]

        for section in pe.sections:
            section_name = section.Name.decode().rstrip('\x00')
            section_data = section.get_data()
            section_entropy = entropy_calculator(section_data)

            is_standard = section_name in standard_sections
            detection_notes = []

            if section_entropy > 7.2:
                detection_notes.append('High entropy may trigger detection')
            if section_name == '.text' and section_entropy > 7.0:
                detection_notes.append('Unusual entropy for code section')
            if not is_standard:
                detection_notes.append('Non-standard section name - may trigger detection')

            sections_info.append({
                'name': section_name,
                'entropy': section_entropy,
                'size': len(section_data),
                'characteristics': section.Characteristics,
                'is_standard': is_standard,
                'detection_notes': detection_notes,
            })

        return sections_info

_security_analyzer_cache = {}


def get_security_analyzer(malapi_path):
    """Return a cached SecurityAnalyzer keyed by malapi_path."""
    if malapi_path not in _security_analyzer_cache:
        _security_analyzer_cache[malapi_path] = SecurityAnalyzer(malapi_path)
    return _security_analyzer_cache[malapi_path]
