rule Windows_VulnDriver_Elby_65b09743 {
    meta:
        author = "Elastic Security"
        id = "65b09743-029d-456a-b7f4-3cd055a0e0e2"
        fingerprint = "88bfab229f2f2d66b4c732a6548ee6f31e6b0905eeea3b8f0f874094c1dbc98a"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: ElbyCDIO.sys, Version: 6.0.3.2"
        threat_name = "Windows.VulnDriver.Elby"
        reference_sample = "eea53103e7a5a55dc1df79797395a2a3e96123ebd71cdd2db4b1be80e7b3f02b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 45 00 6C 00 62 00 79 00 43 00 44 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x06][\x00-\x00])([\x00-\x02][\x00-\x00])([\x00-\x03][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x05][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x06][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

