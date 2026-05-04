rule Windows_VulnDriver_Cpuz_a53d1446 {
    meta:
        author = "Elastic Security"
        id = "a53d1446-ebf7-44f3-843c-2ea5f043e168"
        fingerprint = "1b74df56b73fa8d178a968427480332c6935e023af295e4fff5810bb66db6aab"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: cpuz.sys, Version: 1.0.4.3"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "8c95d28270a4a314299cf50f05dcbe63033b2a555195d2ad2f678e09e00393e6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x04][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x03][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

