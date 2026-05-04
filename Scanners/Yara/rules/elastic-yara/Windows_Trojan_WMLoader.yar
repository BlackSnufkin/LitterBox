rule Windows_Trojan_WMLoader_d2c7b963 {
    meta:
        author = "Elastic Security"
        id = "d2c7b963-8f99-4201-bc57-fdf2c0bd0c13"
        fingerprint = "085c487b7ba3070f3959e9bb287c702050d19812e1fd9b0ef56b098e6310f199"
        creation_date = "2025-12-03"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.WMLoader"
        reference_sample = "fff31726d253458f2c29233d37ee4caf43c5252f58df76c0dced71c4014d6902"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq1 = { 8B 44 24 20 FF C0 89 44 24 20 81 7C 24 20 01 30 00 00 }
        $seq2 = { 41 B8 20 00 00 00 BA 01 30 00 00 48 8B 4C 24 30 E8 ?? ?? ?? ?? 85 C0 75 07 B8 07 00 00 00 EB }
    condition:
        all of them
}

