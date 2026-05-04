rule Windows_VulnDriver_ThreatFire_cbe7ac92 {
    meta:
        author = "Elastic Security"
        id = "cbe7ac92-062e-4781-b46b-71eb5096ca6b"
        fingerprint = "db3932950c8db0b145b0995fa90753ddded4ce1c89f891dce9b0e51a95157dc8"
        creation_date = "2024-08-19"
        last_modified = "2024-09-30"
        threat_name = "Windows.VulnDriver.ThreatFire"
        reference_sample = "1c1a4ca2cbac9fe5954763a20aeb82da9b10d028824f42fff071503dcbe15856"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 66 00 53 00 79 00 73 00 4D 00 6F 00 6E 00 2E 00 73 00 79 00 73 00 00 00 }
        $str1 = "ThreatFire" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and all of them
}

