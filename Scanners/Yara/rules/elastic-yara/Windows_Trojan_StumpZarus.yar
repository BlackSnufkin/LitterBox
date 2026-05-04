rule Windows_Trojan_StumpZarus_3f13c4a2 {
    meta:
        author = "Elastic Security"
        id = "3f13c4a2-9d1f-4c08-8313-549676c1e5bc"
        fingerprint = "fd55ac27ef464ab7ae5d561c2a4f500e45805324511e20da219a0e420ff92cbc"
        creation_date = "2024-12-27"
        last_modified = "2025-02-11"
        threat_name = "Windows.Trojan.StumpZarus"
        reference_sample = "8e84a13620e269ace4ebcae88b8fc81e3df40cf60116919938a4b6e3d7945352"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $binary_0 = { B8 AB AA AA AA D1 EA 8D 1C 95 01 00 00 00 F7 E1 8D 0C AD 08 00 00 00 8B FA B8 AB AA AA AA 41 89 5B 18 }
        $str_0 = "GetProcAddress Error|"
        $str_1 = "Dll Data Error|"
        $str_2 = "%04d-%02d-%02d %02d:%02d:%02d"
        $str_3 = "Hash error!"
        $str_4 = "Sleeping|"
    condition:
        $binary_0 or all of ($str_*)
}

