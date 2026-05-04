rule Windows_VulnDriver_Atillk_18316dd9 {
    meta:
        author = "Elastic Security"
        id = "18316dd9-0a58-4e06-bebd-13f3de45c054"
        fingerprint = "74d618e50edf662aae13e7577a02cfc54c5a15045b34acdb2f5714ce8c65a487"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        description = "Name: atillk64.sys, Version: 5.11.9.0"
        threat_name = "Windows.VulnDriver.Atillk"
        reference_sample = "ad40e6d0f77c0e579fb87c5106bf6de3d1a9f30ee2fbf8c9c011f377fa05f173"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 74 00 69 00 6C 00 6C 00 6B 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x0b][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x09][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x04][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x0a][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x0b][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x08][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

