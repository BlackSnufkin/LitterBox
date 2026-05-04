rule Windows_Trojan_DustyWarehouse_a6cfc9f7 {
    meta:
        author = "Elastic Security"
        id = "a6cfc9f7-6d4a-4904-8294-790243eca76a"
        fingerprint = "a0ef31535c7df8669e2b0cf38e9128e662bf64decabac5c9f3dad3a98f811033"
        creation_date = "2023-08-25"
        last_modified = "2023-11-02"
        threat_name = "Windows.Trojan.DustyWarehouse"
        reference_sample = "8c4de69e89dcc659d2fff52d695764f1efd7e64e0a80983ce6d0cb9eeddb806c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%4d.%2d.%2d-%2d:%2d:%2d" wide fullword
        $a2 = ":]%d-%d-%d %d:%d:%d" wide fullword
        $a3 = "\\sys.key" wide fullword
        $a4 = "[rwin]" wide fullword
        $a5 = "Software\\Tencent\\Plugin\\VAS" fullword
    condition:
        3 of them
}

rule Windows_Trojan_DustyWarehouse_3fef514b {
    meta:
        author = "Elastic Security"
        id = "3fef514b-9499-47ce-bf84-8393f8d0260f"
        fingerprint = "077bc59b4b6298e405c1cd37d9416667371190e5d8c83a9a9502753c9065df58"
        creation_date = "2024-05-30"
        last_modified = "2024-06-12"
        threat_name = "Windows.Trojan.DustyWarehouse"
        reference_sample = "4ad024f53595fdd380f5b5950b62595cd47ac424d2427c176a7b2dfe4e1f35f7"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 83 EC 30 48 C7 44 24 20 FE FF FF FF 48 89 5C 24 48 48 89 74 24 50 C7 44 24 40 [4] 48 8B 39 48 8B 71 08 48 8B 59 10 48 8B 49 18 ?? ?? ?? ?? ?? ?? 84 DB 74 05 E8 E1 01 00 00 48 8B CE }
    condition:
        all of them
}

