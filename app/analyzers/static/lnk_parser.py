#!/usr/bin/env python3
"""
LNK Forensics Module
-------------------
Comprehensive Windows LNK file parser for forensic analysis and malware research.

Usage:
    from lnk_forensics import LnkForensics
    
    # Parse from file path
    lnk = LnkForensics("suspicious.lnk")
    
    # Parse from file handle
    with open("file.lnk", "rb") as f:
        lnk = LnkForensics(file_handle=f)
    
    # Parse from raw data
    lnk = LnkForensics(raw_data=lnk_bytes)
    
    # Get target command (most important for security analysis)
    command = lnk.get_target_command()
    
    # Get all forensic data
    forensic_data = lnk.get_forensic_data()
    
    # Get specific data categories
    timestamps = lnk.get_timestamps()
    machine_info = lnk.get_machine_tracking()
    network_info = lnk.get_network_info()
"""

import os
import struct
import datetime
import hashlib
from typing import Dict, List, Optional, Union, Any

class LnkForensicsError(Exception):
    """Custom exception for LNK parsing errors."""
    pass

class LnkForensics:
    """
    Comprehensive LNK file forensic parser.
    
    Extracts all available forensic artifacts from Windows LNK files including:
    - Target execution paths and arguments
    - Machine tracking identifiers
    - Timestamps and file attributes
    - Network share information
    - Volume and drive details
    - Environment variables and metadata
    """
    
    def __init__(self, file_path: str = None, file_handle = None, raw_data: bytes = None):
        """
        Initialize LNK parser with file path, file handle, or raw data.
        
        Args:
            file_path: Path to LNK file
            file_handle: Open file handle
            raw_data: Raw LNK file bytes
        """
        self.file_path = file_path
        self.indata = None
        self.parsed = False
        self.parse_error = None
        
        # Initialize data structures
        self.linkFlag = {}
        self.fileFlag = {}
        self.data = {}
        self.extraBlocks = {}
        self.lnk_header = {}
        self.loc_information = {}
        
        # Load data
        if file_path:
            self._load_from_path(file_path)
        elif file_handle:
            self._load_from_handle(file_handle)
        elif raw_data:
            self._load_from_data(raw_data)
        else:
            raise LnkForensicsError("Must provide file_path, file_handle, or raw_data")
        
        # Define constants
        self._init_constants()
        
        # Parse the LNK file
        self._parse()
    
    def _load_from_path(self, file_path: str):
        """Load LNK data from file path."""
        try:
            with open(file_path, 'rb') as f:
                self.indata = f.read()
        except Exception as e:
            raise LnkForensicsError(f"Failed to read file {file_path}: {e}")
    
    def _load_from_handle(self, file_handle):
        """Load LNK data from file handle."""
        try:
            self.indata = file_handle.read()
        except Exception as e:
            raise LnkForensicsError(f"Failed to read from file handle: {e}")
    
    def _load_from_data(self, raw_data: bytes):
        """Load LNK data from raw bytes."""
        if not isinstance(raw_data, bytes):
            raise LnkForensicsError("raw_data must be bytes")
        self.indata = raw_data
    
    def _init_constants(self):
        """Initialize parsing constants."""
        self.DRIVE_TYPES = [
            'DRIVE_UNKNOWN', 'DRIVE_NO_ROOT_DIR', 'DRIVE_REMOVABLE',
            'DRIVE_FIXED', 'DRIVE_REMOTE', 'DRIVE_CDROM', 'DRIVE_RAMDISK'
        ]
        
        self.WINDOWSTYLES = [
            'SW_HIDE', 'SW_NORMAL', 'SW_SHOWMINIMIZED', 'SW_MAXIMIZE',
            'SW_SHOWNOACTIVATE', 'SW_SHOW', 'SW_MINIMIZE', 'SW_SHOWMINNOACTIVE',
            'SW_SHOWNA', 'SW_RESTORE', 'SW_SHOWDEFAULT'
        ]
    
    @staticmethod
    def _clean_line(rstring: bytes) -> str:
        """Clean binary string to readable text."""
        return ''.join(chr(i) for i in rstring if 128 > i > 20)
    
    def _ms_time_to_unix_time(self, time: int) -> str:
        """Convert Windows FILETIME to human readable format."""
        try:
            return datetime.datetime.fromtimestamp(time / 10000000.0 - 11644473600).strftime('%Y-%m-%d %H:%M:%S')
        except:
            return "Invalid timestamp"
    
    def _read_string(self, index: int) -> str:
        """Read null-terminated string from data."""
        result = ''
        while index < len(self.indata) and self.indata[index] != 0x00:
            result += chr(self.indata[index])
            index += 1
        return result
    
    def _read_string_data(self, index: int, u_mult: int) -> tuple:
        """Read length-prefixed string data."""
        if index + 2 > len(self.indata):
            return index, ""
        try:
            string_size = struct.unpack('<H', self.indata[index: index + 2])[0] * u_mult
            if index + 2 + string_size > len(self.indata):
                return index + 2, ""
            string = self._clean_line(self.indata[index + 2: index + 2 + string_size].replace(b'\x00', b''))
            new_index = index + string_size + 2
            return new_index, string
        except:
            return index + 2, ""
    
    def _parse_lnk_header(self) -> bool:
        """Parse the 76-byte LNK header."""
        try:
            if len(self.indata) < 76:
                return False
                
            self.lnk_header['header_size'] = struct.unpack('<I', self.indata[:4])[0]
            if self.lnk_header['header_size'] != 76:
                return False
                
            lnk_header = self.indata[:76]
            
            self.lnk_header['guid'] = lnk_header[4:20].hex()
            self.lnk_header['rlinkFlags'] = struct.unpack('<i', lnk_header[20:24])[0]
            self.lnk_header['rfileFlags'] = struct.unpack('<i', lnk_header[24:28])[0]
            self.lnk_header['creation_time'] = struct.unpack('<q', lnk_header[28:36])[0]
            self.lnk_header['accessed_time'] = struct.unpack('<q', lnk_header[36:44])[0]
            self.lnk_header['modified_time'] = struct.unpack('<q', lnk_header[44:52])[0]
            self.lnk_header['file_size'] = struct.unpack('<i', lnk_header[52:56])[0]
            self.lnk_header['icon_index'] = struct.unpack('<I', lnk_header[56:60])[0]
            
            # Window style
            windowstyle_val = struct.unpack('<i', lnk_header[60:64])[0]
            if 0 <= windowstyle_val < len(self.WINDOWSTYLES):
                self.lnk_header['windowstyle'] = self.WINDOWSTYLES[windowstyle_val]
            else:
                self.lnk_header['windowstyle'] = windowstyle_val
                
            self.lnk_header['hotkey'] = struct.unpack('<H', lnk_header[64:66])[0]
            self.lnk_header['reserved0'] = struct.unpack('<H', lnk_header[66:68])[0]
            self.lnk_header['reserved1'] = struct.unpack('<i', lnk_header[68:72])[0]
            self.lnk_header['reserved2'] = struct.unpack('<i', lnk_header[72:76])[0]
            
            return True
        except Exception as e:
            self.parse_error = f"Header parsing failed: {e}"
            return False
    
    def _parse_link_flags(self):
        """Parse and decode link flags."""
        flags = self.lnk_header['rlinkFlags']
        self.linkFlag = {
            'HasTargetIDList': bool(flags & 0x00000001),
            'HasLinkInfo': bool(flags & 0x00000002),
            'HasName': bool(flags & 0x00000004),
            'HasRelativePath': bool(flags & 0x00000008),
            'HasWorkingDir': bool(flags & 0x00000010),
            'HasArguments': bool(flags & 0x00000020),
            'HasIconLocation': bool(flags & 0x00000040),
            'IsUnicode': bool(flags & 0x00000080),
            'ForceNoLinkInfo': bool(flags & 0x00000100),
            'HasExpString': bool(flags & 0x00000200),
            'RunInSeparateProcess': bool(flags & 0x00000400),
            'HasDarwinID': bool(flags & 0x00001000),
            'RunAsUser': bool(flags & 0x00002000),
            'HasExpIcon': bool(flags & 0x00004000),
            'NoPidlAlias': bool(flags & 0x00008000),
            'RunWithShimLayer': bool(flags & 0x00020000),
            'ForceNoLinkTrack': bool(flags & 0x00040000),
            'EnableTargetMetadata': bool(flags & 0x00080000),
            'DisableLinkPathTracking': bool(flags & 0x00100000),
            'DisableKnownFolderTracking': bool(flags & 0x00200000),
            'DisableKnownFolderAlias': bool(flags & 0x00400000),
            'AllowLinkToLink': bool(flags & 0x00800000),
            'UnaliasOnSave': bool(flags & 0x01000000),
            'PreferEnvironmentPath': bool(flags & 0x02000000),
            'KeepLocalIDListForUNCTarget': bool(flags & 0x04000000),
        }
    
    def _parse_file_flags(self):
        """Parse and decode file attribute flags."""
        flags = self.lnk_header['rfileFlags']
        self.fileFlag = {
            'FILE_ATTRIBUTE_READONLY': bool(flags & 0x00000001),
            'FILE_ATTRIBUTE_HIDDEN': bool(flags & 0x00000002),
            'FILE_ATTRIBUTE_SYSTEM': bool(flags & 0x00000004),
            'FILE_ATTRIBUTE_DIRECTORY': bool(flags & 0x00000010),
            'FILE_ATTRIBUTE_ARCHIVE': bool(flags & 0x00000020),
            'FILE_ATTRIBUTE_DEVICE': bool(flags & 0x00000040),
            'FILE_ATTRIBUTE_NORMAL': bool(flags & 0x00000080),
            'FILE_ATTRIBUTE_TEMPORARY': bool(flags & 0x00000100),
            'FILE_ATTRIBUTE_SPARSE_FILE': bool(flags & 0x00000200),
            'FILE_ATTRIBUTE_REPARSE_POINT': bool(flags & 0x00000400),
            'FILE_ATTRIBUTE_COMPRESSED': bool(flags & 0x00000800),
            'FILE_ATTRIBUTE_OFFLINE': bool(flags & 0x00001000),
            'FILE_ATTRIBUTE_NOT_CONTENT_INDEXED': bool(flags & 0x00002000),
            'FILE_ATTRIBUTE_ENCRYPTED': bool(flags & 0x00004000),
            'FILE_ATTRIBUTE_VIRTUAL': bool(flags & 0x00010000),
        }
    
    def _parse_distributed_tracker_block(self, index: int, size: int):
        """Parse distributed link tracker block for machine tracking."""
        try:
            self.extraBlocks['DISTRIBUTED_LINK_TRACKER_BLOCK'] = {
                'size': struct.unpack('<I', self.indata[index + 8: index + 12])[0],
                'version': struct.unpack('<I', self.indata[index + 12: index + 16])[0],
                'machine_identifier': self._clean_line(self.indata[index + 16: index + 32]),
                'droid_volume_identifier': self.indata[index + 32: index + 48].hex(),
                'droid_file_identifier': self.indata[index + 48: index + 64].hex(),
                'birth_droid_volume_identifier': self.indata[index + 64: index + 80].hex(),
                'birth_droid_file_identifier': self.indata[index + 80: index + 96].hex(),
            }
        except:
            pass
    
    def _parse_environment_block(self, index: int, size: int):
        """Parse environment variables block."""
        try:
            self.extraBlocks['ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK'] = {
                'size': size,
                'variable_location': self._clean_line(self.indata[index + 8: index + 8 + size])
            }
        except:
            pass
    
    def _get_enabled_flags(self, flags_dict: Dict[str, bool]) -> List[str]:
        """Get list of enabled flags."""
        return [flag for flag, enabled in flags_dict.items() if enabled]
    
    def _parse(self):
        """Main parsing method."""
        try:
            if not self._parse_lnk_header():
                raise LnkForensicsError(f"Invalid LNK header: {self.parse_error}")
            
            self._parse_link_flags()
            self._parse_file_flags()
            index = self.lnk_header['header_size']
            
            # Skip LinkTargetIDList if present
            if self.linkFlag['HasTargetIDList']:
                try:
                    targets_size = struct.unpack('<H', self.indata[index: index + 2])[0]
                    index += 2 + targets_size
                except:
                    pass
            
            # Parse LinkInfo if present  
            if self.linkFlag['HasLinkInfo'] and not self.linkFlag['ForceNoLinkInfo']:
                try:
                    self.loc_information = {
                        'LinkInfoSize': struct.unpack('<i', self.indata[index: index + 4])[0],
                        'LinkInfoHeaderSize': struct.unpack('<i', self.indata[index + 4: index + 8])[0],
                        'LinkInfoFlags': struct.unpack('<i', self.indata[index + 8: index + 12])[0],
                        'VolumeIDOffset': struct.unpack('<i', self.indata[index + 12: index + 16])[0],
                        'LocalBasePathOffset': struct.unpack('<i', self.indata[index + 16: index + 20])[0],
                        'CommonNetworkRelativeLinkOffset': struct.unpack('<i', self.indata[index + 20: index + 24])[0],
                        'CommonPathSuffixOffset': struct.unpack('<i', self.indata[index + 24: index + 28])[0],
                    }
                    
                    # Parse volume information if present
                    if self.loc_information['LinkInfoFlags'] & 0x0001:
                        if self.loc_information['LocalBasePathOffset'] != 0:
                            local_index = index + self.loc_information['LocalBasePathOffset']
                            self.loc_information['LocalBasePath'] = self._read_string(local_index)
                        
                        local_index = index + self.loc_information['VolumeIDOffset']
                        self.loc_information['VolumeIDAndLocalBasePath'] = {
                            'VolumeIDSize': struct.unpack('<i', self.indata[local_index + 0: local_index + 4])[0],
                            'rDriveType': struct.unpack('<i', self.indata[local_index + 4: local_index + 8])[0],
                            'DriveSerialNumber': hex(struct.unpack('<i', self.indata[local_index + 8: local_index + 12])[0]),
                            'VolumeLabelOffset': struct.unpack('<i', self.indata[local_index + 12: local_index + 16])[0],
                        }
                        
                        # Add drive type string
                        drive_type = self.loc_information['VolumeIDAndLocalBasePath']['rDriveType']
                        if 0 <= drive_type < len(self.DRIVE_TYPES):
                            self.loc_information['VolumeIDAndLocalBasePath']['DriveType'] = self.DRIVE_TYPES[drive_type]
                        
                        # Parse volume label if present
                        if self.loc_information['VolumeIDAndLocalBasePath']['VolumeLabelOffset'] != 20:
                            vol_offset = self.loc_information['VolumeIDAndLocalBasePath']['VolumeLabelOffset']
                            vol_size = self.loc_information['VolumeIDAndLocalBasePath']['VolumeIDSize']
                            length = vol_size - vol_offset
                            label_index = index + self.loc_information['VolumeIDOffset'] + vol_offset
                            if label_index + length <= len(self.indata):
                                self.loc_information['VolumeIDAndLocalBasePath']['VolumeLabel'] = \
                                    self._clean_line(self.indata[label_index: label_index + length].replace(b'\x00', b''))
                    
                    # Parse network information if present
                    elif self.loc_information['LinkInfoFlags'] & 0x0002:
                        local_index = index + self.loc_information['CommonNetworkRelativeLinkOffset']
                        self.loc_information['CommonNetworkRelativeLinkAndPathSuffix'] = {
                            'CommonNetworkRelativeLinkSize': struct.unpack('<i', self.indata[local_index + 0: local_index + 4])[0],
                            'CommonNetworkRelativeLinkFlags': struct.unpack('<i', self.indata[local_index + 4: local_index + 8])[0],
                            'NetNameOffset': struct.unpack('<i', self.indata[local_index + 8: local_index + 12])[0],
                            'DeviceNameOffset': struct.unpack('<i', self.indata[local_index + 12: local_index + 16])[0],
                            'NetworkProviderType': struct.unpack('<i', self.indata[local_index + 16: local_index + 20])[0],
                        }
                    
                    index += self.loc_information['LinkInfoSize']
                except:
                    pass
            
            # Parse string data
            try:
                u_mult = 2 if self.linkFlag['IsUnicode'] else 1
                
                if self.linkFlag['HasName']:
                    index, self.data['description'] = self._read_string_data(index, u_mult)
                
                if self.linkFlag['HasRelativePath']:
                    index, self.data['relativePath'] = self._read_string_data(index, u_mult)
                
                if self.linkFlag['HasWorkingDir']:
                    index, self.data['workingDirectory'] = self._read_string_data(index, u_mult)
                
                if self.linkFlag['HasArguments']:
                    index, self.data['commandLineArguments'] = self._read_string_data(index, u_mult)
                
                if self.linkFlag['HasIconLocation']:
                    index, self.data['iconLocation'] = self._read_string_data(index, u_mult)
            except:
                pass
            
            # Parse extra blocks
            extra_sigs = {
                'a0000001': self._parse_environment_block,
                'a0000003': self._parse_distributed_tracker_block,
            }
            
            try:
                while index <= len(self.indata) - 10:
                    try:
                        size = struct.unpack('<I', self.indata[index: index + 4])[0]
                        if size < 4:
                            break
                        sig = str(hex(struct.unpack('<I', self.indata[index + 4: index + 8])[0]))[2:]
                        if sig in extra_sigs:
                            extra_sigs[sig](index, size)
                        index += size
                    except:
                        break
            except:
                pass
            
            self.parsed = True
            
        except Exception as e:
            self.parse_error = str(e)
            raise LnkForensicsError(f"Parsing failed: {e}")
    
    def is_valid(self) -> bool:
        """Check if LNK file was successfully parsed."""
        return self.parsed and self.parse_error is None
    
    def get_error(self) -> Optional[str]:
        """Get parsing error if any."""
        return self.parse_error
    
    def get_target_command(self) -> str:
        """
        Get the complete target command that the LNK file executes.
        
        Returns:
            Complete command string including arguments
        """
        if not self.parsed:
            return ""
        
        out = ''
        if self.linkFlag.get('HasRelativePath') and 'relativePath' in self.data:
            out += self.data['relativePath']
        if self.linkFlag.get('HasArguments') and 'commandLineArguments' in self.data:
            out += ' ' + self.data['commandLineArguments']
        return out.strip()
    
    def get_timestamps(self) -> Dict[str, str]:
        """
        Get all timestamps from the LNK file.
        
        Returns:
            Dictionary with creation, modified, and accessed times
        """
        if not self.parsed:
            return {}
        
        return {
            'creation_time': self._ms_time_to_unix_time(self.lnk_header.get('creation_time', 0)),
            'modified_time': self._ms_time_to_unix_time(self.lnk_header.get('modified_time', 0)),
            'accessed_time': self._ms_time_to_unix_time(self.lnk_header.get('accessed_time', 0)),
        }
    
    def get_machine_tracking(self) -> Dict[str, str]:
        """
        Get machine tracking information for attribution.
        
        Returns:
            Dictionary with machine identifier and DROID identifiers
        """
        if not self.parsed:
            return {}
        
        tracker = self.extraBlocks.get('DISTRIBUTED_LINK_TRACKER_BLOCK', {})
        return {
            'machine_identifier': tracker.get('machine_identifier', ''),
            'droid_volume_identifier': tracker.get('droid_volume_identifier', ''),
            'droid_file_identifier': tracker.get('droid_file_identifier', ''),
            'birth_droid_volume_identifier': tracker.get('birth_droid_volume_identifier', ''),
            'birth_droid_file_identifier': tracker.get('birth_droid_file_identifier', ''),
        }
    
    def get_network_info(self) -> Dict[str, Any]:
        """
        Get network share information if present.
        
        Returns:
            Dictionary with network share details
        """
        if not self.parsed:
            return {}
        
        return self.loc_information.get('CommonNetworkRelativeLinkAndPathSuffix', {})
    
    def get_volume_info(self) -> Dict[str, Any]:
        """
        Get volume and drive information.
        
        Returns:
            Dictionary with drive type, serial, and volume label
        """
        if not self.parsed:
            return {}
        
        vol_info = self.loc_information.get('VolumeIDAndLocalBasePath', {})
        result = {
            'drive_type': vol_info.get('DriveType', ''),
            'drive_serial': vol_info.get('DriveSerialNumber', ''),
            'volume_label': vol_info.get('VolumeLabel', ''),
            'local_base_path': self.loc_information.get('LocalBasePath', '')
        }
        return {k: v for k, v in result.items() if v}
    
    def get_file_hashes(self) -> Dict[str, str]:
        """
        Calculate file hashes for the LNK file.
        
        Returns:
            Dictionary with MD5, SHA1, and SHA256 hashes
        """
        if not self.indata:
            return {}
        
        return {
            'md5': hashlib.md5(self.indata).hexdigest(),
            'sha1': hashlib.sha1(self.indata).hexdigest(),
            'sha256': hashlib.sha256(self.indata).hexdigest(),
        }
    
    def get_link_flags(self) -> Dict[str, Any]:
        """
        Get link flags information.
        
        Returns:
            Dictionary with raw value and enabled flags
        """
        if not self.parsed:
            return {}
        
        return {
            'raw_value': f"0x{self.lnk_header.get('rlinkFlags', 0):08X}",
            'enabled_flags': self._get_enabled_flags(self.linkFlag)
        }
    
    def get_file_attributes(self) -> Dict[str, Any]:
        """
        Get file attributes information.
        
        Returns:
            Dictionary with raw value and enabled attributes
        """
        if not self.parsed:
            return {}
        
        return {
            'raw_value': f"0x{self.lnk_header.get('rfileFlags', 0):08X}",
            'enabled_attributes': self._get_enabled_flags(self.fileFlag)
        }
    
    def get_target_info(self) -> Dict[str, str]:
        """
        Get all target-related information.
        
        Returns:
            Dictionary with target command, paths, and arguments
        """
        if not self.parsed:
            return {}
        
        return {
            'target_command': self.get_target_command(),
            'description': self.data.get('description', ''),
            'relative_path': self.data.get('relativePath', ''),
            'working_directory': self.data.get('workingDirectory', ''),
            'command_line_arguments': self.data.get('commandLineArguments', ''),
            'icon_location': self.data.get('iconLocation', ''),
        }
    
    def get_forensic_data(self) -> Dict[str, Any]:
        """
        Get comprehensive forensic data from the LNK file.
        
        Returns:
            Complete dictionary with all extracted forensic artifacts
        """
        if not self.parsed:
            return {'error': self.parse_error or 'File not parsed'}
        
        forensic_data = {
            'file_info': {
                'filename': os.path.basename(self.file_path) if self.file_path else 'unknown',
                'file_size_bytes': len(self.indata),
                **self.get_file_hashes()
            },
            'lnk_header': {
                'header_size': self.lnk_header.get('header_size'),
                'guid': self.lnk_header.get('guid'),
                'target_file_size': self.lnk_header.get('file_size'),
                'icon_index': self.lnk_header.get('icon_index'),
                'window_style': self.lnk_header.get('windowstyle'),
                'hotkey': self.lnk_header.get('hotkey'),
                **self.get_timestamps()
            },
            'link_flags': self.get_link_flags(),
            'file_attributes': self.get_file_attributes(),
            'target_info': self.get_target_info(),
            'volume_info': self.get_volume_info(),
            'network_info': self.get_network_info(),
            'machine_tracking': self.get_machine_tracking(),
            'environment_info': self.extraBlocks.get('ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK', {}),
            'extra_blocks': [block for block in self.extraBlocks.keys() 
                           if block not in ['DISTRIBUTED_LINK_TRACKER_BLOCK', 'ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK']]
        }
        
        return forensic_data
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary format for JSON serialization.
        
        Returns:
            Dictionary representation of all forensic data
        """
        return self.get_forensic_data()


# Convenience functions for quick analysis
def analyze_lnk_file(file_path: str) -> Dict[str, Any]:
    """
    Quick analysis of LNK file.
    
    Args:
        file_path: Path to LNK file
    
    Returns:
        Complete forensic analysis dictionary
    """
    try:
        lnk = LnkForensics(file_path)
        return lnk.get_forensic_data()
    except Exception as e:
        return {'error': str(e)}

def get_lnk_command(file_path: str) -> str:
    """
    Extract just the target command from LNK file.
    
    Args:
        file_path: Path to LNK file
    
    Returns:
        Target command string
    """
    try:
        lnk = LnkForensics(file_path)
        return lnk.get_target_command()
    except:
        return ""

def get_lnk_machine_id(file_path: str) -> str:
    """
    Extract machine identifier for attribution.
    
    Args:
        file_path: Path to LNK file
    
    Returns:
        Machine identifier string
    """
    try:
        lnk = LnkForensics(file_path)
        tracking = lnk.get_machine_tracking()
        return tracking.get('machine_identifier', '')
    except:
        return ""


if __name__ == "__main__":
    # Example usage when run as script
    import sys
    import json
    
    if len(sys.argv) != 2:
        print("Usage: python lnk_forensics.py <lnk_file>")
        sys.exit(1)
    
    try:
        lnk = LnkForensics(sys.argv[1])
        print(json.dumps(lnk.get_forensic_data(), indent=2))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)