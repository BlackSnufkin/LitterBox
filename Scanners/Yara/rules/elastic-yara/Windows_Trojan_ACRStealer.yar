rule Windows_Trojan_ACRStealer_f9728d76 {
    meta:
        author = "Elastic Security"
        id = "f9728d76-0b57-4a4f-93de-9d8590301416"
        fingerprint = "d1308f5a32426666fce76a4777becbfc6f90ffa12b8ef2b8ee7ab2f9ede203b5"
        creation_date = "2025-05-01"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.ACRStealer"
        reference_sample = "120316ecaf06b76a564ce42e11f7074c52df6d79b85d3526c5b4e9f362d2f1c2"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 0F B6 45 ?? 83 F8 30 7C ?? 0F B6 4D ?? 83 F9 39 7E ?? 0F B6 55 ?? 83 FA 41 7C ?? 0F B6 45 ?? 83 F8 5A 7E ?? 0F B6 4D ?? 83 F9 61 7C ?? 0F B6 55 ?? 83 FA 7A 7E ?? 0F B6 45 ?? 83 F8 2B 74 ?? 0F B6 4D ?? 83 F9 2F 74 ?? C7 45 ?? ?? ?? ?? ?? EB ?? C7 45 }
        $a2 = "Error: no GetSystemMetrics" ascii fullword
        $a3 = "Error: no user32.dll" ascii fullword
        $a4 = { 8B ?? 24 C7 ?? ?? ?? ?? ?? 8B ?? F8 5? E8 ?? ?? ?? ?? 83 C4 04 8B ?? FC 5? FF 15 ?? ?? ?? ?? 33 C0 E9 }
        $a5 = { 89 45 F8 8B 45 F8 8B 88 A4 00 00 00 89 4D F4 8B 55 F8 }
    condition:
        3 of them
}

