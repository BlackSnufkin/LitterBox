rule Windows_Trojan_Winos_464b8a2e {
    meta:
        author = "Elastic Security"
        id = "464b8a2e-851c-45eb-89fe-ea265b01514a"
        fingerprint = "e626d858981a4f44d63d61f124413e617e1b63755b10dd3089805758bc809b01"
        creation_date = "2025-05-08"
        last_modified = "2025-05-27"
        threat_name = "Windows.Trojan.Winos"
        reference_sample = "ea57f741eeb76fb77cd84fbb1ff7b33d00772b751d20cbc0ce8dc3278db141af"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "CLSID\\{%.8X-%.4X-%.4X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X%.2X}" wide fullword
        $a2 = "d33f351a4aeea5e608853d1a56661059" wide fullword
        $a3 = "%s-%04d%02d%02d-%02d%02d%02d.dmp" wide fullword
        $a4 = "Windows\\System32\\tracerpt.exe" wide fullword
        $a5 = "Software\\Tencent\\Plugin\\VAS" wide fullword
        $a6 = "onlyloadinmyself" wide fullword
        $a7 = "IpDatespecial" wide fullword
        $a8 = "IpDates_info" wide fullword
        $a9 = "Console\\0" wide fullword
        $a10 = "Console\\1" wide fullword
    condition:
        4 of them
}

rule Windows_Trojan_Winos_a60d5880 {
    meta:
        author = "Elastic Security"
        id = "a60d5880-a262-4969-b253-afd62c12239d"
        fingerprint = "cf050833c79a1366abd1f0c0256d46d6bc3aeafb2fa1d747e1af522c05fa5200"
        creation_date = "2025-11-25"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Winos"
        reference_sample = "227e0b3b3fc053df623109e3f100ae7c5a9659bb05bf7db35878ad867f26904e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 8B ?? 24 [1-4] 48 89 44 24 ?? 48 8B 44 24 ?? 0F B7 00 3D 4D 5A 00 00 74 }
        $a2 = { 44 89 44 24 18 48 89 54 24 10 48 89 4C 24 08 48 83 EC 68 48 8B 44 24 78 48 89 05 }
        $a3 = { 33 D2 48 8D 0D [2] 00 00 E8 [2] 00 00 48 8B 00 48 89 ?? 24 }
        $a4 = { 44 89 4C 24 20 4C 89 44 24 18 48 89 54 24 10 48 89 4C 24 08 48 81 EC ?8 02 00 00 BA ?? 00 00 00 48 8D ?C 24 }
        $a5 = { 89 54 24 10 48 89 4C 24 08 48 83 EC ?8 48 8B 44 24 ?0 48 8D 0D [2] 00 00 48 89 08 48 8B 44 24 ?0 8B 4C 24 ?? 89 48 }
        $a6 = { 8B 44 24 [2] 8? C0 48 8B 54 24 ?? 48 8D 4C 24 20 E8 [4] 8B 44 24 ?? 4? 8? C0 48 8B 54 24 ?? 48 8D 4C 24 20 E8 }
        $a7 = { FE AA CA 48 8B 4? 24 ?0 89 0? 48 8B 4? 24 ?? 48 8B 4? 24 ?? 48 89 48 08 48 8B 4? 24 ?0 48 8B 4? 24 }
        $a8 = { C1 E0 05 8B 4C 24 ?? C1 E9 1B 0? C? 69 C0 23 BB D9 44 89 44 24 ?? 8B 44 24 ?? C1 E8 0B }
    condition:
        4 of them
}

