rule Windows_Trojan_WineLoader_13e8860a {
    meta:
        author = "Elastic Security"
        id = "13e8860a-9d83-4ae6-b07e-20bb4037010c"
        fingerprint = "d21c6d97360deea724b94b8f65116f00c11625c5deb1bac0790a23ede6eaaac6"
        creation_date = "2024-03-24"
        last_modified = "2024-05-08"
        threat_name = "Windows.Trojan.WineLoader"
        reference_sample = "f5cb3234eff0dbbd653d5cdce1d4b1026fa9574ebeaf16aaae3d4e921b6a7f9d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 8B 1E 48 89 F1 E8 ?? ?? 00 00 48 8B 56 08 48 89 F9 49 89 D8 E8 ?? ?? FF FF 48 89 F1 E8 ?? 5C 00 00 90 48 81 C4 ?? 00 00 00 5B 5D 5F 5E 41 5C 41 5E 41 5F C3 C3 41 57 41 56 41 55 41 54 56 57 }
        $a2 = { 85 C0 0F 84 ?? 03 00 00 4C 8D A4 24 BC 00 00 00 41 C7 04 24 04 00 00 00 B8 0F 00 00 00 48 8D 7C 24 70 48 89 47 F8 48 B8 }
        $a3 = { 48 85 DB 0F 84 B3 00 00 00 83 BC 24 80 01 00 00 00 0F 84 5A 01 00 00 4C 8D 74 24 50 49 C7 46 F8 0D 00 00 00 48 B8 }
    condition:
        any of them
}

