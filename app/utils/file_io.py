# app/utils/file_io.py
"""File ingestion: type detection, PE/Office/LNK metadata, upload handling."""
import datetime
import hashlib
import json
import mimetypes
import os
import pathlib
import struct

import pefile
from werkzeug.utils import secure_filename

from ..analyzers.static.lnk_parser import LnkForensics
from .forensics import calculate_entropy, get_security_analyzer
from .risk_analyzer import RiskCalculator


class FileTypeDetector:
    """Detect file format from magic bytes and internal structure."""

    MZ = b"MZ"
    CFBF = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    ZIP_PK = b"PK\x03\x04"
    LNK_HEADER = b"\x4C\x00\x00\x00"

    PE_MACHINES = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}

    @classmethod
    def detect_file_type(cls, filepath):
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
        try:
            with open(filepath, 'rb') as f:
                header = f.read(76)

            lnk_guid = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"
            if len(header) >= 20 and header[4:20] == lnk_guid:
                return {"family": "lnk", "type": "windows_shortcut"}
            else:
                return {"family": "lnk", "type": "invalid"}

        except Exception:
            return {"family": "lnk", "type": "error"}

    @classmethod
    def _detect_pe_type(cls, path):
        try:
            with path.open('rb') as fp:
                fp.seek(0x3C)
                pe_offset = struct.unpack('<I', fp.read(4))[0]

                fp.seek(pe_offset)
                if fp.read(4) != b'PE\x00\x00':
                    return {"family": "pe", "type": "corrupted"}

                machine, _, _, _, _, opt_header_size, characteristics = struct.unpack(
                    '<HHIIIHH', fp.read(20)
                )

                opt_header = fp.read(opt_header_size)
                if len(opt_header) < 70:
                    return {"family": "pe", "type": "corrupted"}

                subsystem = struct.unpack_from('<H', opt_header, 68)[0]

                is_dll = bool(characteristics & 0x2000)
                is_system = bool(characteristics & 0x1000)
                is_driver = is_system or subsystem in (1, 11, 12)

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
                    "outlinecache": "one",
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
        try:
            import zipfile
            with zipfile.ZipFile(filepath) as z:
                names = {n.lower() for n in z.namelist()}

                if "[content_types].xml" in names:
                    ooxml_types = {
                        "word/document.xml": "docx",
                        "xl/workbook.xml": "xlsx",
                        "ppt/presentation.xml": "pptx",
                        "visio/document.xml": "vsdx",
                    }

                    for path, file_type in ooxml_types.items():
                        if path in names:
                            return {"family": "office", "type": file_type}

                    return {"family": "office", "type": "ooxml-unknown"}

                if "mimetype" in names:
                    try:
                        with z.open("mimetype") as f:
                            mimetype = f.read().decode('utf-8').strip()

                        odt_types = {
                            "opendocument.text": "odt",
                            "opendocument.spreadsheet": "ods",
                            "opendocument.presentation": "odp",
                        }

                        for mime_part, file_type in odt_types.items():
                            if mime_part in mimetype:
                                return {"family": "office", "type": file_type}
                    except Exception:
                        pass

                return {"family": "zip", "type": "zip"}
        except zipfile.BadZipFile:
            return {"family": "zip", "type": "corrupted"}
        except Exception:
            return {"family": "zip", "type": "error"}


def detect_file_type(filepath):
    """Detect file type by magic bytes (delegates to FileTypeDetector)."""
    return FileTypeDetector.detect_file_type(filepath)


def get_pe_info(filepath, malapi_path):
    """Build a PE metadata dict including imports, sections, and risk notes."""
    try:
        pe = pefile.PE(filepath)
        analyzer = get_security_analyzer(malapi_path)

        suspicious_imports, build_with = analyzer.analyze_pe_imports(pe)
        sections_info = analyzer.analyze_pe_sections(pe, calculate_entropy)

        is_valid_checksum = pe.verify_checksum()
        calculated_checksum = pe.generate_checksum()
        stored_checksum = pe.OPTIONAL_HEADER.CheckSum

        malware_categories = {}
        if suspicious_imports:
            for imp in suspicious_imports:
                category = imp.get('category', 'Unknown')
                malware_categories[category] = malware_categories.get(category, 0) + 1

        info = {
            'file_type': (
                'PE32+ executable'
                if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
                else 'PE32 executable'
            ),
            'machine_type': pefile.MACHINE_TYPE.get(
                pe.FILE_HEADER.Machine, f"UNKNOWN ({pe.FILE_HEADER.Machine})"
            ).replace('IMAGE_FILE_MACHINE_', ''),
            'compile_time': datetime.datetime.fromtimestamp(
                pe.FILE_HEADER.TimeDateStamp
            ).strftime('%Y-%m-%d %H:%M:%S'),
            'subsystem': pefile.SUBSYSTEM_TYPE.get(
                pe.OPTIONAL_HEADER.Subsystem, f"UNKNOWN ({pe.OPTIONAL_HEADER.Subsystem})"
            ).replace('IMAGE_SUBSYSTEM_', ''),
            'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'sections': sections_info,
            'imports': list({
                entry.dll.decode()
                for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
            }),
            'suspicious_imports': suspicious_imports,
            'malware_categories': malware_categories,
            'detection_notes': _build_pe_detection_notes(
                is_valid_checksum, suspicious_imports,
                malware_categories, sections_info, build_with,
            ),
            'build_with': build_with,
            'checksum_info': {
                'is_valid': is_valid_checksum,
                'stored_checksum': hex(stored_checksum),
                'calculated_checksum': hex(calculated_checksum),
                'needs_update': calculated_checksum != stored_checksum,
                'build_with': build_with,
            },
        }

        pe.close()
        return {'pe_info': info}
    except Exception as e:
        print(f"Error analyzing PE file: {e}")
        return {'pe_info': None}


def _build_pe_detection_notes(is_valid_checksum, suspicious_imports,
                              malware_categories, sections_info, build_with=None):
    detection_notes = []

    if not is_valid_checksum:
        if build_with == 'go':
            detection_notes.append(
                'Go binary with non-standard PE checksum - This is normal for Go binaries'
            )
        elif build_with == 'rust':
            detection_notes.append(
                'Rust binary with non-standard PE checksum - This is normal for Rust binaries'
            )
        else:
            detection_notes.append(
                'Invalid PE checksum - Common in modified/packed files '
                '(~83% correlation with malware)'
            )

    if suspicious_imports:
        if build_with == 'go':
            detection_notes.append(
                f'Go binary detected: {len(suspicious_imports)} imports found are typically '
                f'part of Go runtime - Not necessarily malicious'
            )
        elif build_with == 'rust':
            detection_notes.append(
                f'Rust binary detected: {len(suspicious_imports)} imports found are typically '
                f'part of Rust runtime - Not necessarily malicious'
            )
        else:
            detection_notes.append(
                f'Found {len(suspicious_imports)} suspicious API imports - Review import analysis'
            )

        for category, count in malware_categories.items():
            if build_with == 'go':
                detection_notes.append(
                    f'Found {count} imports in category "{category}" (Go runtime related)'
                )
            elif build_with == 'rust':
                detection_notes.append(
                    f'Found {count} imports in category "{category}" (Rust runtime related)'
                )
            else:
                detection_notes.append(
                    f'Found {count} suspicious imports in category "{category}"'
                )

        if not build_with:
            high_risk_categories = {
                'Injection': 'WARNING: Process injection capabilities detected',
                'Ransomware': 'WARNING: File encryption/ransomware capabilities detected',
                'Anti-Debugging': 'WARNING: Anti-analysis techniques detected',
            }

            for category, warning in high_risk_categories.items():
                if category in malware_categories:
                    detection_notes.append(warning)

    if any(section['entropy'] > 7.2 for section in sections_info):
        detection_notes.append(
            'High entropy sections detected - Consider entropy reduction techniques'
        )

    text_sections = [s for s in sections_info if s['name'] == '.text']
    if text_sections and text_sections[0]['entropy'] > 7.0:
        detection_notes.append('Packed/encrypted code section may trigger heuristics')

    if any(not section['is_standard'] for section in sections_info):
        detection_notes.append(
            'Non-standard PE sections detected - May trigger static analysis'
        )

    return detection_notes


def get_office_info(filepath, malapi_path):
    """Analyze Office macros (delegates to SecurityAnalyzer)."""
    return get_security_analyzer(malapi_path).analyze_office_macros(filepath)


def get_lnk_info(filepath):
    """Analyze a Windows .LNK shortcut for forensic data."""
    try:
        lnk = LnkForensics(filepath)
        if not lnk.is_valid():
            return {'lnk_info': None}

        forensic_data = lnk.get_forensic_data()
        return {'lnk_info': forensic_data}

    except Exception as e:
        print(f"Error analyzing LNK file: {e}")
        return {'lnk_info': None}


def _build_entropy_analysis(entropy_value):
    analysis = {
        'value': entropy_value,
        'detection_risk': (
            'High' if entropy_value > 7.2
            else 'Medium' if entropy_value > 6.8
            else 'Low'
        ),
        'notes': [],
    }

    if entropy_value > 7.2:
        analysis['notes'].append(
            'High entropy indicates encryption/packing - consider entropy reduction'
        )
    elif entropy_value > 6.8:
        analysis['notes'].append('Moderate entropy - may trigger basic detection')

    return analysis


def save_uploaded_file(file, config):
    """Persist an uploaded file, compute hashes/entropy/PE info, and write file_info.json."""
    file_content = file.read()
    file.close()

    md5_hash = hashlib.md5(file_content).hexdigest()
    sha256_hash = hashlib.sha256(file_content).hexdigest()

    original_filename = secure_filename(file.filename)
    extension = os.path.splitext(original_filename)[1].lower()
    filename = f"{md5_hash}_{original_filename}"

    upload_folder = config['utils']['upload_folder']
    result_folder = config['utils']['result_folder']
    malapi_path = config['utils']['malapi_path']

    os.makedirs(upload_folder, exist_ok=True)
    filepath = os.path.join(upload_folder, filename)
    os.makedirs(result_folder, exist_ok=True)
    os.makedirs(os.path.join(result_folder, filename), exist_ok=True)

    with open(filepath, 'wb') as f:
        f.write(file_content)

    entropy_value = calculate_entropy(file_content)
    file_type_info = detect_file_type(filepath)

    file_info = {
        'original_name': original_filename,
        'md5': md5_hash,
        'sha256': sha256_hash,
        'size': len(file_content),
        'extension': file_type_info['type'],
        'mime_type': mimetypes.guess_type(original_filename)[0] or 'application/octet-stream',
        'upload_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'entropy': entropy_value,
        'entropy_analysis': _build_entropy_analysis(entropy_value),
        'detected_type': file_type_info,
    }

    if file_type_info['family'] == 'pe':
        file_info.update(get_pe_info(filepath, malapi_path))

        if file_info.get('pe_info'):
            pe_info = file_info['pe_info']
            build_with = pe_info.get('build_with')

            risk_score = 0
            risk_factors = []

            if build_with in ['go', 'rust']:
                risk_score = 15
                risk_factors.append(
                    f"Binary built with {build_with.upper()} - Runtime imports expected"
                )
            else:
                pe_risk, pe_factors = RiskCalculator.calculate_pe_risk(pe_info)
                risk_score = pe_risk
                risk_factors.extend(pe_factors)

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
                'factors': risk_factors,
            }

    elif file_type_info['family'] == 'office':
        office_result = get_office_info(filepath, malapi_path)
        if 'error' not in office_result:
            file_info.update(office_result)

    elif file_type_info['family'] == 'lnk':
        lnk_result = get_lnk_info(filepath)
        if 'error' not in lnk_result:
            file_info.update(lnk_result)

    with open(os.path.join(result_folder, filename, 'file_info.json'), 'w') as f:
        json.dump(file_info, f)

    return file_info
