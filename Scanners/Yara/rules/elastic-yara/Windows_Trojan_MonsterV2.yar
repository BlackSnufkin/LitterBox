rule Windows_Trojan_MonsterV2_b3c04bf5 {
    meta:
        author = "Elastic Security"
        id = "b3c04bf5-944e-4db1-8267-f116a9b10725"
        fingerprint = "767342229a583dcecf4f946c1b81424890f4a3fa7d5c2b4639232f2224dbf756"
        creation_date = "2025-07-29"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.MonsterV2"
        reference_sample = "a0800889f8126dcf82ac6e5238f50e7e297201c1810c401b3bef87ebd8c40808"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "anti_dbg" fullword
        $a2 = "aurotun" fullword
        $a3 = "build_name" fullword
        $a4 = "disable_mutex" fullword
        $a5 = "seal_pk" fullword
        $a6 = "sign_pk" fullword
    condition:
        5 of them
}

