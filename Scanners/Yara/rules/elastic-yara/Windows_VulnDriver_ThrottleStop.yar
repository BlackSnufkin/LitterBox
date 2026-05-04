rule Windows_VulnDriver_ThrottleStop_166b7608 {
    meta:
        author = "Elastic Security"
        id = "166b7608-f65c-4bb1-9986-4fb99542ebf4"
        fingerprint = "944d96cd7dadc43e327ef96e54498ed9956a7896ce080e9e849f2057827e5fc0"
        creation_date = "2025-12-10"
        last_modified = "2026-02-02"
        description = "Subject: TechPowerUp LLC, Version: <= 3.0.0.0"
        threat_name = "Windows.VulnDriver.ThrottleStop"
        reference_sample = "16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 63 68 50 6F 77 65 72 55 70 20 4C 4C 43 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
        $str1 = "Driver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

