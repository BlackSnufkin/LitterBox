rule Windows_Trojan_KoiLoader_1131bc57 {
    meta:
        author = "Elastic Security"
        id = "1131bc57-69f5-466f-859a-bc7e74bf78cc"
        fingerprint = "1a62d483f76259bc6531a11a2d5de7171298341586b41c3f28b6e3561701844a"
        creation_date = "2025-03-05"
        last_modified = "2025-05-27"
        threat_name = "Windows.Trojan.KoiLoader"
        reference_sample = "cea8d5807cff4a8b639cdc801c2fa43d1268cf232ebec6a182dd6f6247cd9493"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_1 = "%s|%d.%d (%d)|%s|%s|%S" fullword
        $str_2 = "%d|%s|%.16s|" fullword
        $str_3 = "%%ProgramData%%\\r%Sr.js" wide fullword
        $str_4 = "sd4.ps1" wide fullword
        $str_5 = "sd2.ps1" wide fullword
        $str_6 = { 4A 65 6E 6E 69 66 65 72 20 4C 6F 70 65 7A 20 26 20 50 69 74 62 75 6C 6C 20 2D 20 4F 6E 20 54 68 65 20 46 6C 6F 6F 72 0D 0A 42 65 79 6F 6E 63 65 20 2D 20 48 61 6C 6F 00 }
    condition:
        3 of them
}

