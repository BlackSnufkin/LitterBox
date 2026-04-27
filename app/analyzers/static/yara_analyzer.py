# app/analyzers/static/yara_analyzer.py
import os
import re
from ..base import BaseSubprocessAnalyzer


class YaraStaticAnalyzer(BaseSubprocessAnalyzer):
    tool_section = 'static'
    tool_name = 'yara'
    target_kwarg = 'file_path'
    extra_format_kwargs = ('rules_path',)

    def _postprocess_findings(self, findings):
        self._map_output_to_rule_strings(findings)
        return findings

    def _build_envelope(self, findings, returncode, stderr, stdout, target):
        return {
            'status': 'completed' if returncode == 0 else 'failed',
            'scan_info': {
                'target': target,
                'rules_file': self.config['analysis']['static']['yara']['rules_path'],
            },
            'matches': findings,
            'errors': stderr if stderr else None,
        }

    def _parse_rule_strings(self, rule_filepath, rule_name):
        strings = {}
        try:
            if not os.path.exists(rule_filepath):
                return strings

            with open(rule_filepath, 'r') as f:
                lines = f.readlines()

            inside_rule = False
            strings_section = False
            for line in lines:
                stripped = line.strip()

                if re.match(r'^rule\s+' + re.escape(rule_name) + r'\s*($|\{)', stripped):
                    inside_rule = True
                elif inside_rule and stripped.startswith("strings:"):
                    strings_section = True
                elif inside_rule and strings_section and stripped.startswith("$"):
                    match = re.match(r'^\$([a-zA-Z0-9_]+)\s*=\s*(.+)$', stripped)
                    if match:
                        identifier = match.group(1)
                        value = re.sub(r'\s+//.+$', '', match.group(2).strip())
                        strings[identifier] = value
                elif inside_rule and stripped.startswith("condition:"):
                    strings_section = False
                elif inside_rule and stripped == "}" and not strings_section:
                    inside_rule = False

        except Exception as e:
            print(f"Error parsing rule file: {e}")

        return strings

    def _map_output_to_rule_strings(self, matches):
        for match in matches:
            rule_name = match['rule']
            rule_filepath = match['metadata'].get('rule_filepath')

            if not rule_filepath:
                threat_name = match['metadata'].get('threat_name')
                if threat_name:
                    rule_filepath = self._get_rule_filepath(threat_name)

                if not rule_filepath and 'description' in match['metadata']:
                    rule_filepath = self._get_rule_filepath_from_description(
                        match['metadata']['description']
                    )

                if not rule_filepath:
                    rule_filepath = self._get_rule_filepath_from_rule_name(rule_name)

                if rule_filepath:
                    match['metadata']['rule_filepath'] = rule_filepath
                else:
                    continue

            rule_strings = self._parse_rule_strings(rule_filepath, rule_name)

            for string in match['strings']:
                identifier = string['identifier'].lstrip('$')
                if identifier in rule_strings:
                    string['data'] = rule_strings[identifier]

    def _parse_output(self, output):
        matches = []
        current_match = None
        current_strings = []

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('YARA Scan Results') \
                    or line == 'Static pattern matching analysis results.':
                continue

            if '[' in line and ']' in line and (re.search(r'\[\s*\w+\s*=', line) or ' matched ' in line):
                if current_match:
                    current_match['strings'] = current_strings
                    matches.append(current_match)
                    current_strings = []

                try:
                    if ' matched ' in line:
                        parts = line.split(' matched ')
                        rule_name = parts[0].strip()
                        target = parts[1].strip()
                        metadata_str = ""
                    else:
                        before_bracket = line.split(' [', 1)
                        rule_name = before_bracket[0].strip()
                        bracket_start = line.find('[')
                        bracket_end = line.rfind(']')

                        if bracket_start != -1 and bracket_end != -1:
                            metadata_str = line[bracket_start + 1:bracket_end]
                            target = line[bracket_end + 1:].strip()
                        else:
                            metadata_str = ""
                            target = line.split(']')[-1].strip()

                    metadata = self._parse_metadata(metadata_str)

                    rule_filepath = None
                    if 'threat_name' in metadata:
                        rule_filepath = self._get_rule_filepath(metadata['threat_name'])
                    elif 'description' in metadata:
                        rule_filepath = self._get_rule_filepath_from_description(metadata['description'])

                    if not rule_filepath:
                        rule_filepath = self._get_rule_filepath_from_rule_name(rule_name)

                    metadata['rule_filepath'] = rule_filepath

                    current_match = {
                        'rule': rule_name,
                        'metadata': metadata,
                        'strings': [],
                        'target_file': target,
                    }
                except Exception as e:
                    print(f"Error parsing rule line: {e}")
                    continue

            elif line.startswith('0x'):
                try:
                    parts = re.split(r':\s+', line, 2)
                    if len(parts) >= 2:
                        offset = parts[0].strip()

                        if len(parts) == 2:
                            identifier = "unnamed_string"
                            string_data = parts[1].strip()
                        else:
                            identifier_parts = parts[1].strip().split(' ')
                            identifier = identifier_parts[0]
                            string_data = parts[2].strip() if len(parts) > 2 else ''

                        current_strings.append({
                            'offset': offset,
                            'identifier': identifier,
                            'data': string_data,
                        })
                except Exception as e:
                    print(f"Error parsing string match: {e}")
                    continue

        if current_match:
            current_match['strings'] = current_strings
            matches.append(current_match)

        return matches

    def _parse_metadata(self, metadata_str):
        metadata = {}
        field_mappings = {
            'date': 'creation_date',
            'modified': 'last_modified',
            'description': 'description',
            'score': 'severity',
        }
        important_fields = {
            'id', 'creation_date', 'threat_name', 'severity',
            'description', 'author', 'date', 'modified', 'score',
        }

        pairs = re.findall(r'([^,\s]+?)\s*=\s*(?:"([^\"]+)"|(\d+)|([^,\s]+))', metadata_str)
        for pair in pairs:
            key = pair[0]
            value = next((v for v in pair[1:] if v), "")

            normalized_key = field_mappings.get(key, key)

            if normalized_key == 'severity' and value:
                try:
                    value = int(value)
                except ValueError:
                    value = 0

            if key in important_fields or normalized_key in important_fields:
                metadata[normalized_key] = value
                if key != normalized_key:
                    metadata[key] = value

        return metadata

    def _get_rule_filepath(self, threat_name):
        if not threat_name:
            return None

        rules_dir = os.path.dirname(self.config['analysis']['static']['yara']['rules_path'])
        rule_filename = threat_name.replace('.', '_')
        if not rule_filename.endswith('.yar'):
            rule_filename += '.yar'

        filepath = os.path.join(rules_dir, rule_filename)
        return filepath if os.path.exists(filepath) else None

    def _get_rule_filepath_from_description(self, description):
        if not description:
            return None

        rules_dir = os.path.dirname(self.config['analysis']['static']['yara']['rules_path'])

        words = re.split(r'[:\s]', description)
        if not words:
            return None

        for i in range(min(4, len(words))):
            potential_name = '_'.join(words[:i + 1]).lower()
            for ext in ['.yar', '.yara']:
                filepath = os.path.join(rules_dir, potential_name + ext)
                if os.path.exists(filepath):
                    return filepath

        return None

    def _get_rule_filepath_from_rule_name(self, rule_name):
        if not rule_name:
            return None

        rules_dir = os.path.dirname(self.config['analysis']['static']['yara']['rules_path'])

        variations = [
            rule_name,
            rule_name.replace('_', '.'),
            rule_name.split('_')[0] if '_' in rule_name else None,
        ]

        for variation in variations:
            if not variation:
                continue
            for ext in ['.yar', '.yara']:
                filepath = os.path.join(rules_dir, variation + ext)
                if os.path.exists(filepath):
                    return filepath

        try:
            for filename in os.listdir(rules_dir):
                if filename.endswith('.yar') or filename.endswith('.yara'):
                    filepath = os.path.join(rules_dir, filename)
                    with open(filepath, 'r') as f:
                        content = f.read()
                        if f"rule {rule_name}" in content or f"rule {rule_name} " in content:
                            return filepath
        except Exception as e:
            print(f"Error scanning rule files: {e}")

        return None
