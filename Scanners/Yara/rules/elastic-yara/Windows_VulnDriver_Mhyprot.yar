rule Windows_VulnDriver_Mhyprot_26214176 {
    meta:
        author = "Elastic Security"
        id = "26214176-1565-4b10-bd7a-901206ef6b29"
        fingerprint = "368c818c0052192c73f078a0ea314e3d2f5d08bc4ef32a27d7e01a40eba68940"
        creation_date = "2022-08-25"
        last_modified = "2022-08-25"
        description = "Subject: miHoYo Co.,Ltd., Version: 1.0.0.0"
        threat_name = "Windows.VulnDriver.Mhyprot"
        reference_sample = "509628b6d16d2428031311d7bd2add8d5f5160e9ecc0cd909f1e82bbbb3234d6"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 6D 69 48 6F 59 6F 20 43 6F 2E 2C 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
        $str1 = "\\Device\\mhyprot2" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

