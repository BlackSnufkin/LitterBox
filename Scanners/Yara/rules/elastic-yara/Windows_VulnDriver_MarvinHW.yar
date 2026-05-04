rule Windows_VulnDriver_MarvinHW_37326842 {
    meta:
        author = "Elastic Security"
        id = "37326842-66a3-4058-abb7-d6d48ca58831"
        fingerprint = "f0ac8176d412dfaeb9c37ce18c13dea7cc2783fd37421b69e19c4dfa898e42be"
        creation_date = "2022-07-21"
        last_modified = "2022-07-21"
        description = "Subject: Marvin Test Solutions, Inc., Name: HW.sys, Version: 4.9.8.0"
        threat_name = "Windows.VulnDriver.MarvinHW"
        reference_sample = "6a4875ae86131a594019dec4abd46ac6ba47e57a88287b814d07d929858fe3e5"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 61 72 76 69 6E 20 54 65 73 74 20 53 6F 6C 75 74 69 6F 6E 73 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 57 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x09][\x00-\x00])([\x00-\x04][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x08][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x08][\x00-\x00])([\x00-\x04][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x09][\x00-\x00])([\x00-\x04][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x07][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version
}

