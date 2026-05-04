rule Windows_Trojan_LegionLoader_9699226a {
    meta:
        author = "Elastic Security"
        id = "9699226a-3299-41c0-8a56-bb9c2db967eb"
        fingerprint = "ff05b5b2a1b05769ba6cb7ba1feccf093d27928b578601c6d038ec51b3caa0db"
        creation_date = "2025-05-01"
        last_modified = "2025-05-27"
        threat_name = "Windows.Trojan.LegionLoader"
        reference_sample = "45670ffa9b24542ae84e3c9eb5ce609c2bcd29129215a7f37eb74b6211e32b22"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 8B EC 83 EC 14 89 4D FC C7 45 F4 00 00 00 00 8D 45 F4 50 8B 4D FC 51 8D 4D EC E8 ?? ?? ?? ?? 8B 55 08 52 8D 4D EC E8 ?? ?? ?? ?? 8B 4D FC E8 DC 0A 00 00 0F B6 C0 85 C0 74 08 0F B6 4D 0C }
    condition:
        all of them
}

