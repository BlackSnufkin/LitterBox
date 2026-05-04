rule Windows_Trojan_DeerStealer_1c08cc82 {
    meta:
        author = "Elastic Security"
        id = "1c08cc82-1c47-4778-bd11-c97dfbfb21ed"
        fingerprint = "52aefc77ab8314777cd12ca2c9f41566958d36e4729446166aac529b1e604e58"
        creation_date = "2026-02-02"
        last_modified = "2026-03-17"
        threat_name = "Windows.Trojan.DeerStealer"
        reference_sample = "721475b73b7b39ca9bee6d2d7d85674f05165a1b6dad439e8bff54f074aa2707"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 8B 01 48 8B 49 08 48 83 C1 08 48 85 C0 }
        $b = { 48 89 44 24 20 48 C7 01 00 00 00 00 48 C7 41 08 00 00 00 00 E8 }
    condition:
        all of them
}

