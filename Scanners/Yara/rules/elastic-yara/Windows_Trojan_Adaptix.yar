rule Windows_Trojan_Adaptix_2779784c {
    meta:
        author = "Elastic Security"
        id = "2779784c-10c6-4404-9b9d-bc6bed56b493"
        fingerprint = "d7b01850f18d6aefefada16d8a80db392fa3d68b9d64a5fbdca9ebe094fe8a4e"
        creation_date = "2025-06-23"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Adaptix"
        reference_sample = "9bbc6a711cd5ba3a1e7d8303e8c72166479a1a189ad382e2b837b1bf64c51a9d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 81 EC A8 01 00 00 48 8B 84 24 C0 01 00 00 48 C7 00 00 00 00 00 48 8B 84 24 C0 01 00 00 48 C7 40 08 00 00 00 00 48 8B 84 24 C0 01 00 00 48 C7 40 10 00 00 00 00 48 8B 84 24 C0 01 00 00 48 C7 }
        $a2 = { 48 83 EC 58 48 8B 4C 24 70 E8 ?? ?? ?? ?? 89 44 24 38 C7 44 24 34 00 00 00 00 48 8D 54 24 34 48 8B 4C 24 70 E8 ?? ?? ?? ?? 48 89 44 24 40 48 8B 4C 24 70 E8 ?? ?? ?? ?? 66 89 44 24 30 }
    condition:
        any of them
}

rule Windows_Trojan_Adaptix_b2cda978 {
    meta:
        author = "Elastic Security"
        id = "b2cda978-2cdf-4ceb-884c-2bc2eeaa6e7c"
        fingerprint = "2f1301b7c1fc34446b3983ce9bf2daa1e5324ad7f35f09e2d8bd6a3e0adcc159"
        creation_date = "2025-10-29"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Adaptix"
        reference_sample = "e7ae542fdade716484aca626cd52ee8120dea6fd9b8e49e40b5637de47ee4896"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 89 03 8B 45 EC 48 98 48 8D 14 C5 00 00 00 00 48 8B 45 20 48 01 D0 48 8B 00 48 85 C0 75 15 48 8B 45 E0 8B 40 10 85 C0 74 0A B8 00 00 00 00 }
        $a2 = { 48 89 45 D0 48 8B 4D 10 E8 4C 9F 00 00 89 C2 48 8D 85 C0 FB FF FF 49 89 D0 BA 00 00 00 00 48 89 C1 E8 D5 DE FF FF 48 83 7D D0 00 74 11 8B 55 E8 48 8B 45 D0 48 89 C1 }
        $a3 = { 8B 53 54 48 89 C6 31 C0 48 39 C2 74 0B 8A 0C 07 88 0C 06 48 FF C0 EB F0 0F B7 43 14 0F B7 4B 06 48 8D 44 03 18 48 83 E9 01 72 2C 44 8B 40 0C 44 8B 48 14 31 D2 44 8B 50 10 49 01 F0 49 01 F9 49 }
        $a4 = { 48 89 45 E0 48 83 7D E0 00 75 17 41 B8 00 00 00 00 BA 00 00 00 00 B9 05 01 00 00 E8 27 E8 FF FF EB 63 4C 8B 4D D0 4C 8D 85 00 FF FF FF 48 8B 55 D8 48 8B 45 20 48 8B 4D E0 48 89 4C 24 20 48 89 }
        $a5 = { 48 83 EC 10 89 4D 10 C7 ?? ?? ?? ?? ?? ?? 8B 45 10 89 45 F8 48 8D 45 FC 0F B6 00 3C DD 75 37 48 8D 45 F8 0F B6 55 13 88 10 48 8D 45 F8 48 83 C0 01 0F B6 55 12 88 10 48 8D 45 F8 48 83 C0 02 }
    condition:
        any of them
}

