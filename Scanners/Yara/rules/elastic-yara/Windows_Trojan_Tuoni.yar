rule Windows_Trojan_Tuoni_f2fc3a3f {
    meta:
        author = "Elastic Security"
        id = "f2fc3a3f-26f1-41dc-8d03-8bb4fa54e35d"
        fingerprint = "953ed61e9149e766b012c2ba74aeb9f50388372d36cc823a49cb7f35e908d60d"
        creation_date = "2026-02-02"
        last_modified = "2026-03-17"
        threat_name = "Windows.Trojan.Tuoni"
        reference_sample = "b6f87f4c97e9971c22b96237ef67e7d3efe7ecf99ccbb4bd6841c95ba29e24dc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "BOF failed: " fullword
        $b = "TuoniAgent.dll" fullword
        $c = { 41 FF C1 66 41 33 C8 41 8B C1 66 89 0C 3A 49 8D 52 02 25 03 00 00 80 7D }
        $d = { FE C9 49 D1 E9 C0 E1 04 41 83 C2 02 44 0A C1 45 88 04 01 }
        $f = { 83 E2 03 03 C2 83 E0 03 2B C2 48 98 48 8B 4C 24 48 0F BE 04 01 8B 4C 24 38 33 C8 8B C1 }
        $g = { 48 63 44 24 24 48 6B C0 12 48 8B 8C 24 B0 01 00 00 48 8B 49 18 0F BE 44 01 11 8B 4C 24 24 03 C8 8B C1 }
    condition:
        3 of them
}

