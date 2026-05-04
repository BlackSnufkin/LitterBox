rule Windows_Trojan_Donutloader_f40e3759 {
    meta:
        author = "Elastic Security"
        id = "f40e3759-2531-4e21-946a-fb55104814c0"
        fingerprint = "a6b9ccd69d871de081759feca580b034e3c5cec788dd5b3d3db033a5499735b5"
        creation_date = "2021-09-15"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Donutloader"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $x64 = { 06 B8 03 40 00 80 C3 4C 8B 49 10 49 8B 81 30 08 00 00 }
        $x86 = { 04 75 EE 89 31 F0 FF 46 04 33 C0 EB 08 83 21 00 B8 02 }
    condition:
        any of them
}

rule Windows_Trojan_Donutloader_5c38878d {
    meta:
        author = "Elastic Security"
        id = "5c38878d-ca94-4fd9-a36e-1ae5fe713ca2"
        fingerprint = "3b55ec6c37891880b53633b936d10f94d2b806db1723875e4ac95f8a34d97150"
        creation_date = "2021-09-15"
        last_modified = "2021-01-13"
        threat_name = "Windows.Trojan.Donutloader"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 24 48 03 C2 48 89 44 24 28 41 8A 00 84 C0 74 14 33 D2 FF C1 }
    condition:
        any of them
}

rule Windows_Trojan_Donutloader_21e801e0 {
    meta:
        author = "Elastic Security"
        id = "21e801e0-b016-48b2-81f5-930e7d3dd318"
        fingerprint = "8b971734d471f281e7c48177096359e8f43578a12e42f6203f55d5e79d9ed09d"
        creation_date = "2024-01-21"
        last_modified = "2024-02-08"
        threat_name = "Windows.Trojan.Donutloader"
        reference_sample = "c3bda62725bb1047d203575bbe033f0f95d4dd6402c05f9d0c69d24bd3224ca6"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 89 45 F0 48 8B 45 F0 48 81 C4 D0 00 00 00 5D C3 55 48 81 EC 60 02 00 00 48 8D AC 24 80 00 00 00 48 89 8D F0 01 00 00 48 89 95 F8 01 00 00 4C 89 85 00 02 00 00 4C 89 8D 08 02 00 00 48 C7 85 }
    condition:
        all of them
}

