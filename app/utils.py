# app/utils.py

import datetime
import glob
import hashlib
import math
import mimetypes
import os
import shutil
import psutil
import pefile
import json
import struct
import pathlib
from functools import lru_cache
from werkzeug.utils import secure_filename
from oletools.olevba import VBA_Parser
import datetime as dt
from flask import render_template
from .analyzers.static.lnk_parser import LnkForensics


# Global runtime imports configuration for easy maintenance
RUNTIME_IMPORTS = {
    'go': {
        'kernel32.dll': {
            'addvectoredexceptionhandler',
            'closehandle',
            'createeventa',
            'createfilea',
            'createiocompletionport',
            'createthread',
            'createwaitabletimerexw',
            'duplicatehandle',
            'exitprocess',
            'freeenvironmentstringsw',
            'getconsolemode',
            'getenvironmentstringsw',
            'getprocaddress',
            'getprocessaffinitymask',
            'getqueuedcompletionstatusex',
            'getstdhandle',
            'getsystemdirectorya',
            'getsysteminfo',
            'getthreadcontext',
            'loadlibrarya',
            'loadlibraryw',
            'postqueuedcompletionstatus',
            'resumethread',
            'setconsolectrlhandler',
            'seterrormode',
            'setevent',
            'setprocesspriorityboost',
            'setthreadcontext',
            'setunhandledexceptionfilter',
            'setwaitabletimer',
            'suspendthread',
            'switchtothread',
            'virtualalloc',
            'virtualfree',
            'virtualquery',
            'waitformultipleobjects',
            'waitforsingleobject',
            'writeconsolew',
            'writefile'
        }
    },
    'rust': {
        'kernel32.dll': {
            'addvectoredexceptionhandler',
            'closehandle',
            'createmutexa',
            'formatmessagew',
            'getconsolemode',
            'getcurrentdirectoryw',
            'getcurrentprocess',
            'getcurrentprocessid',
            'getcurrentthread',
            'getcurrentthreadid',
            'getenvironmentvariablew',
            'getlasterror',
            'getmodulehandlea',
            'getmodulehandlew',
            'getprocaddress',
            'getprocessheap',
            'getstdhandle',
            'getsystemtimeasfiletime',
            'heapalloc',
            'heapfree',
            'heaprealloc',
            'initializeslisthead',
            'isdebuggerpresent',
            'isprocessorfeaturepresent',
            'loadlibrarya',
            'multibytetowidechar',
            'queryperformancecounter',
            'releasemutex',
            'rtlcapturecontext',
            'rtllookupfunctionentry',
            'rtlvirtualunwind',
            'setlasterror',
            'setthreadstackguarantee',
            'setunhandledexceptionfilter',
            'unhandledexceptionfilter',
            'waitforsingleobject',
            'waitforsingleobjectex',
            'widechartomultibyte',
            'writeconsolew',
            'lstrlenw',
        },
        'ntdll.dll': {
            'ntwritefile',
            'rtlntstatustodoserror'
        }
    }
}




class FileTypeDetector:
    """Centralized file type detection with magic bytes and structure analysis"""
    
# Magic byte signatures
    MZ = b"MZ"  # PE files
    CFBF = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"  # Compound File (old Office)
    ZIP_PK = b"PK\x03\x04"  # ZIP (OOXML, ODT, etc.)
    LNK_HEADER = b"\x4C\x00\x00\x00"  # LNK files (76 byte header)
    
    # PE machines (architectures)
    PE_MACHINES = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}
    
    @classmethod
    def detect_file_type(cls, filepath):
        """Detect file type based on magic bytes and internal structure"""
        try:
            p = pathlib.Path(filepath)
            with p.open('rb') as fp:
                header = fp.read(20)
            
            if header.startswith(cls.MZ):
                return cls._detect_pe_type(p)
            elif header.startswith(cls.CFBF):
                return cls._detect_ole_type(filepath)
            elif header.startswith(cls.ZIP_PK):
                return cls._detect_zip_type(filepath)
            elif header.startswith(cls.LNK_HEADER):
                return cls._detect_lnk_type(filepath)
            
            return {"family": "unknown", "type": "unknown"}
        
        except Exception as e:
            return {"family": "error", "type": str(e)}
    
    @classmethod
    def _detect_lnk_type(cls, filepath):
        """Detect LNK file type"""
        try:
            with open(filepath, 'rb') as f:
                header = f.read(76)
            
            # Verify LNK GUID at offset 4
            lnk_guid = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"
            if len(header) >= 20 and header[4:20] == lnk_guid:
                return {"family": "lnk", "type": "windows_shortcut"}
            else:
                return {"family": "lnk", "type": "invalid"}
                
        except Exception:
            return {"family": "lnk", "type": "error"}

    
    @classmethod
    def _detect_pe_type(cls, path):
        """Detect PE file type and architecture"""
        try:
            with path.open('rb') as fp:
                fp.seek(0x3C)
                pe_offset = struct.unpack('<I', fp.read(4))[0]
                
                fp.seek(pe_offset)
                if fp.read(4) != b'PE\x00\x00':
                    return {"family": "pe", "type": "corrupted"}
                
                machine, _, _, _, _, opt_header_size, characteristics = struct.unpack('<HHIIIHH', fp.read(20))
                
                opt_header = fp.read(opt_header_size)
                if len(opt_header) < 70:
                    return {"family": "pe", "type": "corrupted"}
                
                subsystem = struct.unpack_from('<H', opt_header, 68)[0]
                
                is_dll = bool(characteristics & 0x2000)  # IMAGE_FILE_DLL
                is_system = bool(characteristics & 0x1000)  # IMAGE_FILE_SYSTEM
                is_driver = is_system or subsystem in (1, 11, 12)  # Native or EFI driver
                
                arch = cls.PE_MACHINES.get(machine, f"0x{machine:x}")
                
                if is_driver:
                    return {"family": "pe", "type": "sys", "arch": arch}
                elif is_dll:
                    return {"family": "pe", "type": "dll", "arch": arch}
                else:
                    return {"family": "pe", "type": "exe", "arch": arch}
        except Exception:
            return {"family": "pe", "type": "corrupted"}
    
    @classmethod
    def _detect_ole_type(cls, filepath):
        """Detect OLE/Compound File type"""
        try:
            import olefile
            if not olefile.isOleFile(filepath):
                return {"family": "office", "type": "invalid"}
            
            with olefile.OleFileIO(filepath) as ole:
                streams = {entry[0].lower() for entry in ole.listdir()}
                
                office_types = {
                    "worddocument": "doc",
                    "workbook": "xls",
                    "book": "xls",
                    "powerpoint document": "ppt",
                    "visio document": "vsd",
                    "outlinecache": "one"
                }
                
                for stream, file_type in office_types.items():
                    if stream in streams:
                        return {"family": "office", "type": file_type}
                
                return {"family": "office", "type": "ole-unknown"}
        except ImportError:
            return {"family": "office", "type": "ole-storage"}
        except Exception:
            return {"family": "office", "type": "corrupted"}
    
    @classmethod
    def _detect_zip_type(cls, filepath):
        """Detect ZIP-based file types"""
        try:
            import zipfile
            with zipfile.ZipFile(filepath) as z:
                names = {n.lower() for n in z.namelist()}
                
                # Office Open XML formats
                if "[content_types].xml" in names:
                    ooxml_types = {
                        "word/document.xml": "docx",
                        "xl/workbook.xml": "xlsx",
                        "ppt/presentation.xml": "pptx",
                        "visio/document.xml": "vsdx"
                    }
                    
                    for path, file_type in ooxml_types.items():
                        if path in names:
                            return {"family": "office", "type": file_type}
                    
                    return {"family": "office", "type": "ooxml-unknown"}
                
                # OpenDocument formats
                if "mimetype" in names:
                    try:
                        with z.open("mimetype") as f:
                            mimetype = f.read().decode('utf-8').strip()
                        
                        odt_types = {
                            "opendocument.text": "odt",
                            "opendocument.spreadsheet": "ods",
                            "opendocument.presentation": "odp"
                        }
                        
                        for mime_part, file_type in odt_types.items():
                            if mime_part in mimetype:
                                return {"family": "office", "type": file_type}
                    except:
                        pass
                
                return {"family": "zip", "type": "zip"}
        except zipfile.BadZipFile:
            return {"family": "zip", "type": "corrupted"}
        except Exception:
            return {"family": "zip", "type": "error"}


class SecurityAnalyzer:
    """Centralized security analysis for PE files and Office documents"""
    
    def __init__(self, malapi_path):
        self.malapi_data = self._load_malapi_data(malapi_path)
        self.dll_function_map = self._build_function_map()
    
    def _load_malapi_data(self, malapi_path):
        """Load MalAPI data with error handling"""
        try:
            with open(malapi_path, "r", encoding="utf-8") as f:
                return json.loads(f.read())
        except Exception as e:
            print(f"Error loading MalAPI database: {e}")
            return {}
    
    def _build_function_map(self):
        """Build optimized lookup dictionary for API functions"""
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
        """Detect if PE is built with Go, Rust, or neither - returns runtime type"""
        try:
            # Check for Rust indicators first
            rust_indicators = [
                b'rustc',
                b'rust_begin_unwind',
                b'rust_panic', 
                b'rust_oom',
                b'__rust_',
                b'.rustc_info',
                b'cargo',
                b'rustup'
            ]
            
            # Check for Rust indicators
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
            
            # Check for Go indicators
            # Go-specific section names (highest confidence)
            go_sections = ['.go.buildinfo', '.go.plt']
            for section in pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                if section_name in go_sections:
                    return "go"
            
            # Look for highly Go-specific strings
            high_confidence_indicators = [
                b'go.buildinfo',      # Go build info section content
                b'runtime.main',      # Go's main runtime function
                b'runtime.goexit',    # Go's goroutine exit function  
                b'runtime.newproc',   # Go's process creation
                b'runtime.mallocgc',  # Go's garbage collector malloc
                b'go.string.',        # Go string type prefix
                b'go.func.',          # Go function type prefix
                b'go.itab.',          # Go interface table prefix
                b'go.mod',            # Go module information
                b'runtime.systemstack', # Go system stack function
                b'go:linkname',       # Go linkname directive
                b'go:nosplit',        # Go nosplit directive
                b'go:noescape',       # Go noescape directive
                b'runtime.schedt',    # Go scheduler type
                b'runtime.g',         # Go goroutine type
                b'runtime.m'          # Go machine type
            ]
            
            # Count how many highly specific Go indicators we find
            go_indicator_count = 0
            for section in pe.sections:
                try:
                    section_data = section.get_data()
                    for indicator in high_confidence_indicators:
                        if indicator in section_data:
                            go_indicator_count += 1
                            # If we find multiple highly specific indicators, it's very likely Go
                            if go_indicator_count >= 2:
                                return "go"
                except Exception:
                    continue
            
            # No runtime detected
            return None
            
        except Exception:
            return None

    def analyze_pe_imports(self, pe):
        """Analyze PE imports for suspicious behavior - using global RUNTIME_IMPORTS"""
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
                
                # Check specific DLL first, then fallback to unknown
                for lookup_dll in [dll_name, "unknown"]:
                    if lookup_dll in self.dll_function_map and func_name in self.dll_function_map[lookup_dll]:
                        category, description = self.dll_function_map[lookup_dll][func_name]
                        
                        # Extract hint value with runtime-specific logic
                        hint_value = None
                        if hasattr(imp, 'import_by_ordinal') and imp.import_by_ordinal:
                            hint_value = imp.ordinal if hasattr(imp, 'ordinal') and imp.ordinal is not None else None
                        else:
                            if hasattr(imp, 'hint') and imp.hint is not None:
                                if build_with in ['go', 'rust'] and imp.hint == 0:
                                    hint_value = None
                                else:
                                    hint_value = imp.hint
                        
                        # Determine if this is actually a runtime import using global RUNTIME_IMPORTS
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
                            'runtime_type': build_with if is_runtime_import else None
                        })
                        break
        
        return suspicious_imports, build_with
    
    def analyze_pe_sections(self, pe, entropy_calculator):
        """Analyze PE sections with entropy and detection notes"""
        sections_info = []
        standard_sections = ['.text', '.data', '.bss', '.rdata', '.edata', '.idata', '.pdata', '.reloc', '.rsrc', '.tls', '.debug']
        
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
                'detection_notes': detection_notes
            })
        
        return sections_info
    
    def analyze_office_macros(self, filepath):
        """Analyze Office document macros for threats"""
        try:
            vbaparser = VBA_Parser(filepath)
            detection_notes = []
            
            info = {
                'file_type': 'Microsoft Office Document',
                'has_macros': vbaparser.detect_vba_macros(),
                'macro_info': None,
                'detection_notes': detection_notes
            }
            
            if vbaparser.detect_vba_macros():
                macro_analysis = vbaparser.analyze_macros()
                info['macro_info'] = macro_analysis
                
                macro_text = str(macro_analysis).lower()
                detection_patterns = {
                    'shell': 'Shell command execution detected',
                    'wscript': 'WScript execution detected',
                    'powershell': 'PowerShell execution detected',
                    'http': 'Network communication detected',
                    'auto': 'Auto-execution mechanism detected',
                    'document_open': 'Document open auto-execution',
                    'windowshide': 'Hidden window execution',
                    'createobject': 'COM object creation detected'
                }
                
                for pattern, note in detection_patterns.items():
                    if pattern in macro_text:
                        detection_notes.append(note)
            
            vbaparser.close()
            return {'office_info': info}
        except Exception as e:
            print(f"Error analyzing Office file: {e}")
            return {'office_info': None}


class RiskCalculator:
    """Centralized risk calculation for both file and process analysis"""
    
    SEVERITY_WEIGHTS = {
        'CRITICAL': 100,
        'HIGH': 80,
        'MEDIUM': 50,
        'LOW': 20,
        'INFO': 5
    }
    
    NUMERIC_SEVERITY_MAP = {
        100: 'CRITICAL',
        80: 'HIGH',
        50: 'MEDIUM',
        20: 'LOW',
        5: 'INFO'
    }
    
    @classmethod
    def calculate_yara_risk(cls, matches):
        """Calculate risk based on YARA matches considering severity levels"""
        if not matches:
            return 0, None

        max_severity_score = 0
        severity_counts = {level: 0 for level in cls.SEVERITY_WEIGHTS}

        for match in matches:
            meta = match.get('metadata', {})
            severity = meta.get('severity', 'MEDIUM')

            if isinstance(severity, int):
                severity = cls.NUMERIC_SEVERITY_MAP.get(severity, 'MEDIUM')
            severity = severity.upper()

            if severity in cls.SEVERITY_WEIGHTS:
                severity_counts[severity] += 1
                max_severity_score = max(max_severity_score, cls.SEVERITY_WEIGHTS[severity])

        total_score = 0
        risk_factors = []

        for severity, count in severity_counts.items():
            if count > 0:
                severity_score = cls.SEVERITY_WEIGHTS[severity]

                if count > 1:
                    additional_score = sum(severity_score * (0.5 ** i) for i in range(1, count))
                    total_score += severity_score + additional_score
                else:
                    total_score += severity_score

                risk_factors.append(f"Found {count} {severity.lower()} severity YARA match{'es' if count > 1 else ''}")

        normalized_score = min(100, total_score / 2)
        return normalized_score, risk_factors
    
    @classmethod
    def calculate_pe_risk(cls, pe_info):
        """Calculate risk from PE information - updated for multi-runtime support"""
        pe_risk = 0
        risk_factors = []
        
        # Enhanced entropy detection
        high_entropy_sections = 0
        very_high_entropy_sections = 0
        for section in pe_info.get('sections', []):
            entropy = section.get('entropy', 0)
            if entropy > 7.5:
                very_high_entropy_sections += 1
                risk_factors.append(f"Critical entropy in section {section.get('name', 'UNKNOWN')}: {entropy:.2f}")
            elif entropy > 7.0:
                high_entropy_sections += 1
                risk_factors.append(f"High entropy in section {section.get('name', 'UNKNOWN')}: {entropy:.2f}")
        
        pe_risk += min(high_entropy_sections * 10 + very_high_entropy_sections * 20, 40)
        
        # Enhanced import analysis
        suspicious_imports = pe_info.get('suspicious_imports', [])
        if suspicious_imports:
            critical_functions = {
                'createremotethread', 'virtualallocex', 'writeprocessmemory',
                'ntmapviewofsection', 'zwmapviewofsection'
            }
            high_risk_functions = {
                'loadlibrarya', 'loadlibraryw', 'getprocaddress',
                'openprocess', 'virtualallocexnuma'
            }
            
            critical_imports = sum(1 for imp in suspicious_imports 
                                if imp.get('function', '').lower() in critical_functions)
            high_risk_imports = sum(1 for imp in suspicious_imports 
                                  if imp.get('function', '').lower() in high_risk_functions)
            
            pe_risk += min(critical_imports * 15 + high_risk_imports * 8, 30)
            if critical_imports > 0 or high_risk_imports > 0:
                risk_factors.append(f"Found {critical_imports} critical process manipulation and {high_risk_imports} high-risk dynamic loading imports")
        
        # Enhanced checksum analysis - updated for multi-runtime support
        if pe_info.get('checksum_info'):
            checksum = pe_info['checksum_info']
            if checksum.get('stored_checksum') != checksum.get('calculated_checksum'):
                # Don't penalize runtime binaries for checksum mismatches
                build_with = checksum.get('build_with')
                if build_with not in ['go', 'rust']:
                    pe_risk += 25
                    risk_factors.append("PE checksum mismatch detected")
        
        return pe_risk, risk_factors


class Utils:
    def __init__(self, config):
        self.config = config
        self.security_analyzer = SecurityAnalyzer(config['utils']['malapi_path'])
        self.file_detector = FileTypeDetector()

    @lru_cache(maxsize=128)
    def allowed_file(self, filename):
        """Check if the uploaded file has an allowed extension with caching"""
        return ('.' in filename and 
                filename.rsplit('.', 1)[1].lower() in self.config['utils']['allowed_extensions'])

    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data with detection insights"""
        if len(data) == 0:
            return 0
        
        if isinstance(data, str):
            data = data.encode()

        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        entropy = 0
        for count in byte_counts.values():
            p_x = count / len(data)
            entropy += -p_x * math.log2(p_x)

        return round(entropy, 2)

    def get_pe_info(self, filepath):
        """Enhanced PE file analysis - updated for multi-runtime support"""
        try:
            pe = pefile.PE(filepath)
            
            suspicious_imports, build_with = self.security_analyzer.analyze_pe_imports(pe)
            sections_info = self.security_analyzer.analyze_pe_sections(pe, self.calculate_entropy)
            
            # Check PE Checksum
            is_valid_checksum = pe.verify_checksum()
            calculated_checksum = pe.generate_checksum()
            stored_checksum = pe.OPTIONAL_HEADER.CheckSum
            
            # Create malware category summary
            malware_categories = {}
            if suspicious_imports:
                for imp in suspicious_imports:
                    category = imp.get('category', 'Unknown')
                    malware_categories[category] = malware_categories.get(category, 0) + 1
            
            info = {
                'file_type': 'PE32+ executable' if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 'PE32 executable',
                'machine_type': pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, f"UNKNOWN ({pe.FILE_HEADER.Machine})").replace('IMAGE_FILE_MACHINE_', ''),
                'compile_time': datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S'),
                'subsystem': pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, f"UNKNOWN ({pe.OPTIONAL_HEADER.Subsystem})").replace('IMAGE_SUBSYSTEM_', ''),
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'sections': sections_info,
                'imports': list(set(entry.dll.decode() for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []))),
                'suspicious_imports': suspicious_imports,
                'malware_categories': malware_categories,
                'detection_notes': self._build_pe_detection_notes(is_valid_checksum, suspicious_imports, malware_categories, sections_info, build_with),
                'build_with': build_with,  # Changed from is_go_binary
                'checksum_info': {
                    'is_valid': is_valid_checksum,
                    'stored_checksum': hex(stored_checksum),
                    'calculated_checksum': hex(calculated_checksum),
                    'needs_update': calculated_checksum != stored_checksum,
                    'build_with': build_with  # Changed from is_go_binary
                }
            }
                    
            pe.close()
            return {'pe_info': info}
        except Exception as e:
            print(f"Error analyzing PE file: {e}")
            return {'pe_info': None}

    def _build_pe_detection_notes(self, is_valid_checksum, suspicious_imports, malware_categories, sections_info, build_with=None):
        """Build detection notes for PE analysis - updated for multi-runtime support"""
        detection_notes = []
        
        if not is_valid_checksum:
            if build_with == 'go':
                detection_notes.append('Go binary with non-standard PE checksum - This is normal for Go binaries')
            elif build_with == 'rust':
                detection_notes.append('Rust binary with non-standard PE checksum - This is normal for Rust binaries')
            else:
                detection_notes.append('Invalid PE checksum - Common in modified/packed files (~83% correlation with malware)')

        if suspicious_imports:
            if build_with == 'go':
                detection_notes.append(f'Go binary detected: {len(suspicious_imports)} imports found are typically part of Go runtime - Not necessarily malicious')
            elif build_with == 'rust':
                detection_notes.append(f'Rust binary detected: {len(suspicious_imports)} imports found are typically part of Rust runtime - Not necessarily malicious')
            else:
                detection_notes.append(f'Found {len(suspicious_imports)} suspicious API imports - Review import analysis')
            
            for category, count in malware_categories.items():
                if build_with == 'go':
                    detection_notes.append(f'Found {count} imports in category "{category}" (Go runtime related)')
                elif build_with == 'rust':
                    detection_notes.append(f'Found {count} imports in category "{category}" (Rust runtime related)')
                else:
                    detection_notes.append(f'Found {count} suspicious imports in category "{category}"')
            
            # Special detection notes for high-risk categories (only for non-runtime binaries)
            if not build_with:
                high_risk_categories = {
                    'Injection': 'WARNING: Process injection capabilities detected',
                    'Ransomware': 'WARNING: File encryption/ransomware capabilities detected',
                    'Anti-Debugging': 'WARNING: Anti-analysis techniques detected'
                }
                
                for category, warning in high_risk_categories.items():
                    if category in malware_categories:
                        detection_notes.append(warning)
        
        if any(section['entropy'] > 7.2 for section in sections_info):
            detection_notes.append('High entropy sections detected - Consider entropy reduction techniques')
        
        text_sections = [s for s in sections_info if s['name'] == '.text']
        if text_sections and text_sections[0]['entropy'] > 7.0:
            detection_notes.append('Packed/encrypted code section may trigger heuristics')

        if any(not section['is_standard'] for section in sections_info):
            detection_notes.append('Non-standard PE sections detected - May trigger static analysis')
        
        return detection_notes

    def get_office_info(self, filepath):
        """Enhanced Office document analysis with detection insights"""
        return self.security_analyzer.analyze_office_macros(filepath)

    def save_uploaded_file(self, file):
        """Save uploaded file and generate comprehensive file information - updated for multi-runtime"""
        file_content = file.read()
        file.close()
        
        # Calculate hashes
        md5_hash = hashlib.md5(file_content).hexdigest()
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        
        # Prepare file paths
        original_filename = secure_filename(file.filename)
        extension = os.path.splitext(original_filename)[1].lower()
        filename = f"{md5_hash}_{original_filename}"
        
        upload_folder = self.config['utils']['upload_folder']
        result_folder = self.config['utils']['result_folder']
        
        # Create directories
        os.makedirs(upload_folder, exist_ok=True)
        filepath = os.path.join(upload_folder, filename)
        os.makedirs(result_folder, exist_ok=True)
        os.makedirs(os.path.join(result_folder, filename), exist_ok=True)
        
        # Save file
        with open(filepath, 'wb') as f:
            f.write(file_content)
        
        # Calculate entropy and detect file type
        entropy_value = self.calculate_entropy(file_content)
        file_type_info = self.file_detector.detect_file_type(filepath)

        # Build basic file info
        file_info = {
            'original_name': original_filename,
            'md5': md5_hash,
            'sha256': sha256_hash,
            'size': len(file_content),
            'extension': file_type_info['type'],
            'mime_type': mimetypes.guess_type(original_filename)[0] or 'application/octet-stream',
            'upload_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'entropy': entropy_value,
            'entropy_analysis': self._build_entropy_analysis(entropy_value),
            'detected_type': file_type_info
        }
        
        # Add specific file type information
        if file_type_info['family'] == 'pe':
            file_info.update(self.get_pe_info(filepath))
            
            # Add risk assessment with new build_with support
            if file_info.get('pe_info'):
                pe_info = file_info['pe_info']
                build_with = pe_info.get('build_with')
                
                # Calculate risk score
                risk_score = 0
                risk_factors = []
                
                if build_with in ['go', 'rust']:
                    # Lower risk for runtime binaries
                    risk_score = 15
                    risk_factors.append(f"Binary built with {build_with.upper()} - Runtime imports expected")
                else:
                    # Use normal risk calculation for other binaries
                    pe_risk, pe_factors = RiskCalculator.calculate_pe_risk(pe_info)
                    risk_score = pe_risk
                    risk_factors.extend(pe_factors)
                
                # Determine risk level
                if risk_score >= 75:
                    risk_level = "Critical"
                elif risk_score >= 50:
                    risk_level = "High"
                elif risk_score >= 25:
                    risk_level = "Medium"
                else:
                    risk_level = "Low"
                
                file_info['risk_assessment'] = {
                    'score': risk_score,
                    'level': risk_level,
                    'factors': risk_factors
                }
                
        elif file_type_info['family'] == 'office':
            office_result = self.get_office_info(filepath)
            if 'error' not in office_result:
                file_info.update(office_result)
        
        elif file_type_info['family'] == 'lnk':
            lnk_result = self.get_lnk_info(filepath)
            if 'error' not in lnk_result:
                file_info.update(lnk_result)
        
        # Save file info
        with open(os.path.join(result_folder, filename, 'file_info.json'), 'w') as f:
            json.dump(file_info, f)
        
        return file_info

    def get_lnk_info(self, filepath):
        """Analyze LNK file using LnkForensics module"""
        try:
            lnk = LnkForensics(filepath)
            if not lnk.is_valid():
                return {'lnk_info': None}
            
            forensic_data = lnk.get_forensic_data()
            return {'lnk_info': forensic_data}
            
        except Exception as e:
            print(f"Error analyzing LNK file: {e}")
            return {'lnk_info': None}

    def _build_entropy_analysis(self, entropy_value):
        """Build entropy analysis with detection risk assessment - no changes needed"""
        analysis = {
            'value': entropy_value,
            'detection_risk': 'High' if entropy_value > 7.2 else 'Medium' if entropy_value > 6.8 else 'Low',
            'notes': []
        }
        
        if entropy_value > 7.2:
            analysis['notes'].append('High entropy indicates encryption/packing - consider entropy reduction')
        elif entropy_value > 6.8:
            analysis['notes'].append('Moderate entropy - may trigger basic detection')
        
        return analysis

    def detect_file_type(self, filepath):
        """Detect file type based on magic bytes and internal structure"""
        return self.file_detector.detect_file_type(filepath)

    def find_file_by_hash(self, file_hash, search_folder):
        """Find a file in the specified folder by its hash"""
        try:
            for filename in os.listdir(search_folder):
                if filename.startswith(file_hash):
                    return os.path.join(search_folder, filename)
        except FileNotFoundError:
            pass
        return None

    def check_tool(self, tool_path):
        """Check if a tool is accessible and executable"""
        return os.path.isfile(tool_path) and os.access(tool_path, os.X_OK)

    def validate_pid(self, pid):
        """Validate if a PID exists and is accessible"""
        try:
            pid = int(pid)
            if pid <= 0:
                return False, "Invalid PID: must be a positive integer"
                
            if not psutil.pid_exists(pid):
                return False, f"Process with PID {pid} does not exist"
                
            try:
                process = psutil.Process(pid)
                process.name()  # Try to access process name to verify permissions
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                return False, f"Cannot access process {pid}: {str(e)}"
                
            return True, None
                
        except ValueError:
            return False, "Invalid PID: must be a number"
        except Exception as e:
            return False, f"Error validating PID: {str(e)}"

    def get_entropy_risk_level(self, entropy):
        """Determine the risk level based on entropy value"""
        if entropy > 7.2:
            return 'High'
        elif entropy > 6.8:
            return 'Medium'
        return 'Low'

    def format_hex(self, value):
        """Format a value as a hexadecimal string"""
        if isinstance(value, str) and value.startswith('0x'):
            return value.lower()
        try:
            return f"0x{int(value):x}"
        except (ValueError, TypeError):
            return str(value)

    def calculate_yara_risk(self, matches):
        """Calculate risk based on YARA matches considering severity levels"""
        return RiskCalculator.calculate_yara_risk(matches)

    def calculate_risk(self, analysis_type='process', file_info=None, static_results=None, dynamic_results=None, byovd_results=None):
        """Unified risk calculation function that handles file, process, and driver analysis"""
        
        risk_score = 0
        risk_factors = []
        
        # *** CRITICAL FIX: Handle driver analysis first ***
        if analysis_type == 'driver':
            if byovd_results:
                byovd_risk, byovd_factors = self._calculate_byovd_risk(byovd_results)
                
                # For drivers, use BYOVD score directly (no weighting needed)
                risk_factors.extend([f"BYOVD: {factor}" for factor in byovd_factors])
                final_score = round(min(max(byovd_risk, 0), 100), 2)
                return final_score, risk_factors
            else:
                return 0, ["No BYOVD analysis available"]
        
        # Define weights for non-driver analysis types
        weights = {
            'file': {'pe_info': 0.10, 'static': 0.50, 'dynamic': 0.40},
            'process': {'dynamic': 1.0}
        }[analysis_type]
        
        # PE Information Risk Calculation (file analysis only)
        if analysis_type == 'file' and file_info and file_info.get('pe_info'):
            pe_risk, pe_factors = RiskCalculator.calculate_pe_risk(file_info['pe_info'])
            risk_factors.extend(pe_factors)
            risk_score += (pe_risk / 100) * weights['pe_info'] * 100
        
        # Static Analysis Risk Calculation (file analysis only)
        if analysis_type == 'file' and static_results:
            static_risk, static_factors = self._calculate_static_risk(static_results)
            risk_factors.extend([f"Static: {factor}" for factor in static_factors])
            risk_score += (static_risk / 100) * weights['static'] * 100
        
        # Dynamic Analysis Risk Calculation (file and process analysis)
        if analysis_type in ['file', 'process'] and dynamic_results:
            dynamic_risk, dynamic_factors = self._calculate_dynamic_risk(dynamic_results, analysis_type)
            risk_factors.extend([f"Dynamic: {factor}" for factor in dynamic_factors])
            risk_score += (dynamic_risk / 100) * weights['dynamic'] * 100
        
        # Final normalization and scaling
        risk_score = self._normalize_risk_score(risk_score, analysis_type, dynamic_results, risk_factors)
        
        return round(min(max(risk_score, 0), 100), 2), risk_factors
    
    def _calculate_byovd_risk(self, byovd_results):
        """Calculate risk based on BYOVD (Bring Your Own Vulnerable Driver) analysis results"""
        risk_score = 0
        risk_factors = []
        
        if not byovd_results:
            return 0, []
        

        
        # Extract data from BYOVD results structure
        findings = byovd_results.get('findings', {})
        summary = findings.get('summary', {})
        detailed = findings.get('detailed_analysis', {})
        

        # Extract key indicators (matching frontend logic)
        is_lol = summary.get('is_loldriver', False)
        win10_blocked = summary.get('is_win10_blocked', False)
        win11_blocked = summary.get('is_win11_blocked', False)
        
        # Calculate "hasDanger" equivalent from frontend - FIXED to match exactly
        critical_imports = detailed.get('critical_imports', '')
        has_terminate_process = detailed.get('has_terminate_process', False)
        has_communication = detailed.get('has_communication', False)
        has_dangerous_imports = detailed.get('has_dangerous_imports', False)
        
        has_danger = bool(
            has_dangerous_imports or
            (isinstance(critical_imports, str) and critical_imports.strip()) or
            has_terminate_process or
            has_communication
        )
        
        # Apply frontend scoring logic exactly
        # Frontend: if (win11 && win10) return 0;
        if win11_blocked and win10_blocked:
            risk_factors.append("Blocked on both Windows 10 and 11 - minimal exploitation potential")
            return 0, risk_factors
        
        # Frontend scoring logic with debug output:
        # if (hasDanger) score += 55;
        if has_danger:
            risk_score += 55
            danger_factors = []
            if has_dangerous_imports:
                danger_factors.append("dangerous imports detected")
            if critical_imports and critical_imports.strip():
                danger_factors.append("critical imports detected")
            if has_terminate_process:
                danger_factors.append("process termination capability")
            if has_communication:
                danger_factors.append("communication mechanisms")
            
            if danger_factors:
                risk_factors.append(f"Dangerous capabilities: {', '.join(danger_factors)}")
        
        # if (!win11) score += 25; else score -= 50;
        if not win11_blocked:
            risk_score += 25
            risk_factors.append("Not blocked on Windows 11")
        else:
            risk_score -= 50
            risk_factors.append("Blocked on Windows 11")
            
        # if (!win10) score += 20; else score -= 20;
        if not win10_blocked:
            risk_score += 20
            risk_factors.append("Not blocked on Windows 10")
        else:
            risk_score -= 20
            risk_factors.append("Blocked on Windows 10")
            
        # if (!isLol) score += 10; else score -= 5;
        if not is_lol:
            risk_score += 10
            risk_factors.append("Not listed in LOLDrivers database")
        else:
            risk_score -= 5
            risk_factors.append("Listed in LOLDrivers database")
        
        # Frontend: return Math.max(0, Math.min(100, score));
        final_score = max(0, min(100, risk_score))
        
        # Add additional context from BYOVD analysis
        if detailed.get('win10_block_reason'):
            risk_factors.append(f"Win10 block reason: {detailed['win10_block_reason']}")
        if detailed.get('win11_block_reason'):
            risk_factors.append(f"Win11 block reason: {detailed['win11_block_reason']}")
                    
        return final_score, risk_factors

    def _calculate_static_risk(self, static_results):
        """Calculate risk from static analysis results"""
        static_risk = 0
        risk_factors = []
        
        # YARA detection scoring
        yara_matches = static_results.get('yara', {}).get('matches', [])
        yara_score, yara_factors = self.calculate_yara_risk(yara_matches)
        if yara_score > 0:
            match_multiplier = min(len(yara_matches) * 0.15 + 1, 1.5)
            static_risk += yara_score * match_multiplier
            risk_factors.extend(yara_factors)
        
        # CheckPLZ analysis
        checkplz_findings = static_results.get('checkplz', {}).get('findings', {})
        if checkplz_findings:
            threat_score = 0
            if checkplz_findings.get('initial_threat'):
                threat_score += 50
                risk_factors.append("Critical: CheckPLZ detected initial threat indicators")
            
            indicators = checkplz_findings.get('threat_indicators', [])
            if indicators:
                indicator_score = min(len(indicators) * 15, 40)
                threat_score += indicator_score
                risk_factors.append(f"Found {len(indicators)} additional threat indicators")
            
            static_risk += threat_score
        
        # File entropy analysis
        if static_results.get('file_entropy'):
            entropy = static_results['file_entropy']
            if entropy > 7.5:
                static_risk += 30
                risk_factors.append(f"Critical overall file entropy: {entropy:.2f}")
            elif entropy > 7.0:
                static_risk += 20
                risk_factors.append(f"High overall file entropy: {entropy:.2f}")
        
        return static_risk, risk_factors

    def _calculate_dynamic_risk(self, dynamic_results, analysis_type):
        """Calculate risk from dynamic analysis results"""
        dynamic_risk = 0
        risk_factors = []
        
        # YARA dynamic detections
        yara_matches = dynamic_results.get('yara', {}).get('matches', [])
        yara_score, yara_factors = self.calculate_yara_risk(yara_matches)
        if yara_score > 0:
            dynamic_risk += yara_score
            risk_factors.extend(yara_factors)
        
        # PE-Sieve scoring
        pesieve_findings = dynamic_results.get('pe_sieve', {}).get('findings', {})
        pesieve_suspicious = int(pesieve_findings.get('total_suspicious', 0))
        if pesieve_suspicious > 0:
            severity_multiplier = 1.5 if pesieve_findings.get('severity') == 'critical' else 1.0
            pe_sieve_score = min(pesieve_suspicious * (20 if analysis_type == 'file' else 15) * severity_multiplier,
                               45 if analysis_type == 'file' else 30)
            dynamic_risk += pe_sieve_score
            risk_factors.append(f"PE-Sieve found {pesieve_suspicious} suspicious indicators")
        
        # Memory anomaly detection
        dynamic_risk += self._calculate_memory_anomaly_risk(dynamic_results, analysis_type, risk_factors)
        
        # Behavior analysis
        dynamic_risk += self._calculate_behavior_risk(dynamic_results, analysis_type, risk_factors)
        
        # HSB detection
        dynamic_risk += self._calculate_hsb_risk(dynamic_results, analysis_type, risk_factors)
        
        return dynamic_risk, risk_factors

    def _calculate_memory_anomaly_risk(self, dynamic_results, analysis_type, risk_factors):
        """Calculate risk from memory anomalies"""
        moneta_findings = dynamic_results.get('moneta', {}).get('findings', {})
        if not moneta_findings:
            return 0
        
        memory_scores = {
            'total_private_rwx': 15 if analysis_type == 'file' else 10,
            'total_modified_code': 12 if analysis_type == 'file' else 10,
            'total_heap_executable': 10,
            'total_modified_pe_header': 10,
            'total_private_rx': 8,
            'total_inconsistent_x': 8,
            'total_missing_peb': 5,
            'total_mismatching_peb': 5
        }
        
        total_score = 0
        anomaly_count = 0
        
        for key, weight in memory_scores.items():
            count = int(moneta_findings.get(key, 0) or 0)
            if count > 0:
                total_score += min(count * weight, weight * 2)
                anomaly_count += count
        
        if anomaly_count > 0:
            risk_factors.append(f"Found {anomaly_count} weighted memory anomalies")
            return min(total_score, 40 if analysis_type == 'file' else 30)
        
        return 0

    def _calculate_behavior_risk(self, dynamic_results, analysis_type, risk_factors):
        """Calculate risk from behavioral analysis"""
        patriot_findings = dynamic_results.get('patriot', {}).get('findings', {})
        if not patriot_findings:
            return 0
        
        behaviors = patriot_findings.get('findings', [])
        behavior_count = len(behaviors)
        
        if behavior_count == 0:
            return 0
        
        severity_scores = {
            'critical': 25 if analysis_type == 'file' else 20,
            'high': 15,
            'medium': 10,
            'low': 5
        }
        
        behavior_score = 0
        for behavior in behaviors:
            severity = behavior.get('severity', 'low')
            behavior_score += severity_scores.get(severity, 5)
        
        risk_factors.append(f"Found {behavior_count} weighted suspicious behaviors")
        return min(behavior_score, 35)

    def _calculate_hsb_risk(self, dynamic_results, analysis_type, risk_factors):
        """Calculate risk from HSB detection"""
        hsb_findings = dynamic_results.get('hsb', {}).get('findings', {})
        if not (hsb_findings and hsb_findings.get('detections')):
            return 0
        
        total_hsb_score = 0
        for detection in hsb_findings['detections']:
            if not detection.get('findings'):
                continue
                
            count = len(detection['findings'])
            severity = detection.get('max_severity', 0)
            
            if analysis_type == 'file':
                severity_multiplier = 1 + (severity * 0.5)
                detection_score = min(count * 15 * severity_multiplier, 40)
            else:
                severity_scores = {0: 10, 1: 15, 2: 20}  # LOW, MID, HIGH
                max_scores = {0: 20, 1: 25, 2: 35}
                detection_score = min(count * severity_scores.get(severity, 10), max_scores.get(severity, 20))
            
            total_hsb_score += detection_score
            
            severity_text = ["LOW", "MID", "HIGH"][min(severity, 2)]
            if severity >= 2:
                risk_factors.append(f"Critical: Found {count} high-severity memory operations")
            else:
                risk_factors.append(f"Found {count} {severity_text} severity memory operations")
        
        return min(total_hsb_score, 45 if analysis_type == 'file' else 35)

    def _normalize_risk_score(self, risk_score, analysis_type, dynamic_results, risk_factors):
        """Normalize and apply final scaling to risk score"""
        if analysis_type == 'file':
            base_score = min(max(risk_score, 0), 100)
            if base_score > 75:
                risk_score = min(base_score * 1.15, 100)
        else:  # process
            yara_matches = dynamic_results.get('yara', {}).get('matches', []) if dynamic_results else []
            pesieve_findings = dynamic_results.get('pe_sieve', {}).get('findings', {}) if dynamic_results else {}
            pesieve_suspicious = int(pesieve_findings.get('total_suspicious', 0))
            
            if len(yara_matches) == 0 and pesieve_suspicious <= 1:
                risk_score = min(risk_score, 65)
            
            if all(f.lower().find('high') == -1 for f in risk_factors):
                risk_score = min(risk_score, 75)
        
        return risk_score

    def get_risk_level(self, risk_score):
        """Convert numerical risk score to categorical risk level"""
        if risk_score >= 75:
            return "Critical"
        elif risk_score >= 50:
            return "High"
        elif risk_score >= 25:
            return "Medium"
        else:
            return "Low"

    def load_json_file(self, filepath):
        """Helper function to safely load JSON files"""
        if not os.path.exists(filepath):
            return None
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading JSON file {filepath}: {str(e)}")
            return None

    def extract_detection_counts(self, results):
        """Extract all detection counts from analysis results"""
        counts = {'yara': 0, 'pesieve': 0, 'moneta': 0, 'patriot': 0, 'hsb': 0}
        
        try:
            # YARA
            yara_matches = results.get('yara', {}).get('matches', [])
            counts['yara'] = len({match.get('rule') for match in yara_matches if match.get('rule')}) if isinstance(yara_matches, list) else 0

            # PE-sieve
            pesieve_findings = results.get('pe_sieve', {}).get('findings', {})
            counts['pesieve'] = int(pesieve_findings.get('total_suspicious', 0) or 0)

            # Moneta - only count actual suspicious findings
            moneta_findings = results.get('moneta', {}).get('findings', {})
            non_detection_fields = ['total_regions', 'total_unsigned_modules', 'scan_duration']
            counts['moneta'] = sum(
                int(moneta_findings.get(key, 0) or 0)
                for key in moneta_findings 
                if key.startswith('total_') and key not in non_detection_fields
            )

            # Patriot
            patriot_findings = results.get('patriot', {}).get('findings', {}).get('findings', [])
            counts['patriot'] = len(patriot_findings) if isinstance(patriot_findings, list) else 0

            # HSB
            hsb_findings = results.get('hsb', {}).get('findings', {})
            if hsb_findings and hsb_findings.get('detections'):
                counts['hsb'] = len(hsb_findings['detections'][0].get('findings', []))

        except (TypeError, ValueError, IndexError):
            pass

        return counts

    def generate_html_report(self, file_info=None, static_results=None, dynamic_results=None, pid=None):
        """Generate comprehensive HTML report using Jinja2 template"""
        is_process_analysis = pid is not None and not file_info
        analysis_type = 'process' if is_process_analysis else 'file'

        risk_score, risk_factors = self.calculate_risk(
            analysis_type=analysis_type,
            file_info=file_info,
            static_results=static_results,
            dynamic_results=dynamic_results
        )
        risk_level = self.get_risk_level(risk_score)

        detections = {}
        if static_results or dynamic_results:
            detections = self.extract_detection_counts(dynamic_results or static_results)

        # Ensure dynamic_results has process_output for template compatibility
        if dynamic_results and is_process_analysis:
            if 'process_output' not in dynamic_results:
                dynamic_results['process_output'] = {
                    'had_output': False,
                    'output': '',
                    'stdout': '',
                    'stderr': ''
                }

        return render_template(
            "report.html",
            generated_on=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            is_process_analysis=is_process_analysis,
            risk_score=risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
            detections=detections,
            file_info=file_info,
            static_results=static_results,
            dynamic_results=dynamic_results,
            pid=pid,
            format_size=self._format_size
        )

    def _format_size(self, size_bytes):
        """Format file size to human-readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} bytes"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"