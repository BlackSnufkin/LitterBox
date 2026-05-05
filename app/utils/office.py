# app/utils/office.py
"""Office document analyzer.

Runs at upload time on Word / Excel / RTF / legacy CFBF binaries (alongside
`get_pe_info`, `get_lnk_info`, `get_html_smuggle_info`). Output lands in
`file_info.office_info`.

Two analysis branches:

  1. olevba -- VBA / XLM macros embedded in the file. Pulls per-module
     source, autoexec triggers, suspicious keyword hits, IOCs.

  2. OOXML rels inspection -- external `attachedTemplate` / `oleObject` /
     `subDocument` / `frame` references. Catches T1221 (Remote Template
     Injection) which is invisible to olevba because the malicious VBA
     lives in a remote .dotm, not in the file itself. Atomic Red Team's
     `Calculator.docx` is the canonical example.
"""

import logging
import xml.etree.ElementTree as ET
import zipfile
from typing import Dict, List

from oletools.olevba import VBA_Parser

logger = logging.getLogger(__name__)


# Relationship Types we care about when they target an external (HTTP/UNC)
# resource. `attachedTemplate` is the T1221 vector. The others pull remote
# content the same way; less common but the same class of risk.
_INTERESTING_RELS = (
    'attachedTemplate',
    'oleObject',
    'subDocument',
    'frame',
    'image',          # rare but seen in malicious docs that fetch tracking pixels
    'hyperlink',
)


def get_office_info(filepath: str, malapi_path=None) -> Dict:
    """Public entry. Returns `{office_info: {...}}` -- mirrors `get_lnk_info` /
    `get_html_smuggle_info` shape so file_io can do `file_info.update(result)`
    without conditionals.

    `malapi_path` is accepted for back-compat with the old SecurityAnalyzer
    delegation but isn't used here -- the office analyzer doesn't need
    MalAPI lookups.
    """
    info = {
        'file_type': 'Microsoft Office Document',
        'has_macros': False,
        'modules': [],          # [{stream, vba_filename, code}]
        'analysis': {
            'autoexec': [],     # [{keyword, description}] auto-execution triggers
            'suspicious': [],   # [{keyword, description}] suspicious keyword hits
            'iocs': [],         # [{type, value}] extracted URLs / IPs / EXEs / etc.
            'hex_strings': [],
            'base64_strings': [],
            'vba_strings': [],
        },
        'external_refs': [],    # external relationship targets (T1221 etc.)
        'detection_notes': [],
    }

    _run_olevba(filepath, info)
    _run_external_rels(filepath, info)

    return {'office_info': info}


def _run_olevba(filepath: str, info: Dict) -> None:
    """Branch 1 -- VBA / XLM macro analysis via oletools.olevba."""
    try:
        vbaparser = VBA_Parser(filepath)
    except Exception as e:
        logger.warning(f"olevba init failed on {filepath}: {e}")
        return

    try:
        if not vbaparser.detect_vba_macros():
            return

        info['has_macros'] = True

        # Per-module source code: (filename, stream_path, vba_filename, vba_code)
        for _, stream, vba_fname, vba_code in vbaparser.extract_macros():
            if vba_code:
                info['modules'].append({
                    'stream': stream,
                    'vba_filename': vba_fname,
                    'code': vba_code,
                })

        # Structured analysis -- olevba returns (kw_type, keyword, description)
        for kw_type, keyword, description in vbaparser.analyze_macros():
            kt = (kw_type or '').lower()
            entry = {'keyword': keyword, 'description': description}
            if kt == 'autoexec':
                info['analysis']['autoexec'].append(entry)
            elif kt == 'suspicious':
                info['analysis']['suspicious'].append(entry)
            elif kt == 'iocs':
                info['analysis']['iocs'].append({'type': keyword, 'value': description})
            elif kt == 'hex string':
                info['analysis']['hex_strings'].append(entry)
            elif kt == 'base64 string':
                info['analysis']['base64_strings'].append(entry)
            elif kt in ('vba string', 'vba_string'):
                info['analysis']['vba_strings'].append(entry)

        a = info['analysis']
        if a['autoexec']:
            info['detection_notes'].append(
                f"{len(a['autoexec'])} auto-execution trigger"
                f"{'s' if len(a['autoexec']) != 1 else ''} detected"
            )
        if a['suspicious']:
            info['detection_notes'].append(
                f"{len(a['suspicious'])} suspicious keyword"
                f"{'s' if len(a['suspicious']) != 1 else ''} in macro body"
            )
        if a['iocs']:
            info['detection_notes'].append(
                f"{len(a['iocs'])} IOC"
                f"{'s' if len(a['iocs']) != 1 else ''} extracted from macro"
            )
    except Exception as e:
        logger.warning(f"olevba analysis failed on {filepath}: {e}")
    finally:
        try:
            vbaparser.close()
        except Exception:
            pass


def _run_external_rels(filepath: str, info: Dict) -> None:
    """Branch 2 -- T1221 / external-relationship inspection."""
    try:
        external = _scan_external_relationships(filepath)
    except Exception as e:
        logger.warning(f"External-rels scan failed on {filepath}: {e}")
        return

    if not external:
        return

    info['external_refs'] = external

    t1221 = [r for r in external if r['relationship'] == 'attachedTemplate']
    if t1221:
        info['detection_notes'].append(
            f"MITRE T1221: Remote Template Injection -- {len(t1221)} "
            f"external `attachedTemplate` reference"
            f"{'s' if len(t1221) != 1 else ''}. "
            f"Malicious VBA likely lives in the remote target, not in this file."
        )

    ole_remote = [r for r in external if r['relationship'] == 'oleObject']
    if ole_remote:
        info['detection_notes'].append(
            f"{len(ole_remote)} external OLE-object reference"
            f"{'s' if len(ole_remote) != 1 else ''} -- remote-fetched embedded payload"
        )

    subdoc = [r for r in external if r['relationship'] == 'subDocument']
    if subdoc:
        info['detection_notes'].append(
            f"{len(subdoc)} external subDocument reference"
            f"{'s' if len(subdoc) != 1 else ''}"
        )


def _scan_external_relationships(filepath: str) -> List[Dict]:
    """Walk every `*.rels` file inside an OOXML container and return the list
    of relationships whose `TargetMode` is `External` AND whose Type is one
    of `_INTERESTING_RELS`. Returns `[]` for non-zip files (legacy CFBF
    .doc/.xls binaries).
    """
    if not zipfile.is_zipfile(filepath):
        return []

    findings: List[Dict] = []
    try:
        with zipfile.ZipFile(filepath) as z:
            rels_files = [n for n in z.namelist() if n.endswith('.rels')]
            for rels_name in rels_files:
                try:
                    data = z.read(rels_name)
                except Exception:
                    continue
                try:
                    root = ET.fromstring(data)
                except ET.ParseError:
                    continue

                for rel in root.iter():
                    tag = rel.tag.rsplit('}', 1)[-1] if '}' in rel.tag else rel.tag
                    if tag != 'Relationship':
                        continue
                    if rel.attrib.get('TargetMode', '').lower() != 'external':
                        continue
                    rel_type = rel.attrib.get('Type', '')
                    target = rel.attrib.get('Target', '')
                    rel_name = rel_type.rsplit('/', 1)[-1] if '/' in rel_type else rel_type
                    if rel_name not in _INTERESTING_RELS:
                        continue
                    findings.append({
                        'rels_file': rels_name,
                        'relationship': rel_name,
                        'target': target,
                        'target_mode': 'External',
                        'full_type': rel_type,
                    })
    except zipfile.BadZipFile:
        pass

    return findings
