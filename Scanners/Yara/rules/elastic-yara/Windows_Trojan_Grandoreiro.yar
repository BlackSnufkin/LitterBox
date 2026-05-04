rule Windows_Trojan_Grandoreiro_51236ba2 {
    meta:
        author = "Elastic Security"
        id = "51236ba2-fdbc-4c46-b57b-27fc1e135486"
        fingerprint = "c3082cc865fc177d8cbabcfcf9fb67317af5f2d28e8eeb95eb04108a558d80d4"
        creation_date = "2022-08-23"
        last_modified = "2023-06-13"
        description = "Grandoreiro rule, target loader and payload"
        threat_name = "Windows.Trojan.Grandoreiro"
        reference_sample = "1bdf381e7080d9bed3f52f4b3db1991a80d3e58120a5790c3d1609617d1f439e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $antivm0 = { B8 68 58 4D 56 BB 12 F7 6C 3C B9 0A 00 00 00 66 BA 58 56 ED B8 01 00 00 00 }
        $antivm1 = { B9 [4] 89 E5 53 51 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 BB 00 00 00 00 B8 01 00 00 00 0F 3F 07 0B }
        $xor0 = { 0F B7 44 70 ?? 33 D8 8D 45 ?? 50 89 5D ?? }
        $xor1 = { 8B 45 ?? 0F B7 44 70 ?? 33 C3 89 45 ?? }
    condition:
        all of them
}

rule Windows_Trojan_Grandoreiro_ac4cea59 {
    meta:
        author = "Elastic Security"
        id = "ac4cea59-af73-48bc-bb00-56dbb51921d8"
        fingerprint = "b9e98970090ef6428e8f7f4c9899ebb15ed631c52a0d7aa01794318dbd68f164"
        creation_date = "2025-11-20"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Grandoreiro"
        reference_sample = "2d01933d1ad64c2025e1c42160e7dc097d1ea229c3436d861093358bc2ebe9d1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { BE 01 00 00 00 8B 45 F0 0F B7 5C 70 FE 33 5D D4 8D 45 F0 E8 ?? ?? ?? ?? 8B D0 8B 45 F0 85 C0 74 }
        $b = { 0F B7 14 5A 8B 4D ?? 0F B7 0C 41 8B 75 ?? 66 89 0C 5E 8B 4D ?? 66 89 14 41 4B 85 DB 75 }
        $c = { 0F B7 4C 50 FE 03 D9 B8 81 80 80 80 F7 EB 03 D3 C1 FA 07 8B C2 C1 E8 1F 03 D0 8B C2 C1 E2 08 2B D0 2B DA 8B 45 D8 48 99 F7 7D DC 8B C2 40 8B 55 F8 0F B7 44 42 FE 33 D8 }
        $d = { 0F B7 44 50 FE 03 C3 B9 FF 00 00 00 99 F7 F9 8B DA 8B 45 D8 48 99 F7 7D DC 8B C2 40 8B 55 F8 0F B7 44 42 FE 33 D8 }
        $e = { 53 8B DA 83 F8 08 0F 87 99 00 00 00 }
        $f = { 53 8B DA 83 F8 0A 0F 87 BD 00 00 00 }
        $g = { 53 8B DA 83 F8 67 0F 87 49 07 00 00 }
    condition:
        3 of ($a, $b, $c, $d) and any of ($e, $f, $g)
}

