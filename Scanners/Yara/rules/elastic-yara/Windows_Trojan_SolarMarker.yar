rule Windows_Trojan_SolarMarker_d466e548 {
    meta:
        author = "Elastic Security"
        id = "d466e548-eb88-41e6-9740-ae59980db835"
        fingerprint = "0f4b0162ee8283959e10c459ddc55eb00eae30d241119aad1aa3ea6c101f9889"
        creation_date = "2023-12-12"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.SolarMarker"
        reference_sample = "330f5067c93041821be4e7097cf32fb569e2e1d00e952156c9aafcddb847b873"
        reference_sample = "e2a620e76352fa7ac58407a711821da52093d97d12293ae93d813163c58eb84b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 00 00 2B 03 00 2B 15 00 07 2D 09 08 16 FE 01 16 FE 01 2B 01 17 00 13 04 11 04 2D 8C 07 2D 06 08 }
    condition:
        all of them
}

rule Windows_Trojan_SolarMarker_08bfc26b {
    meta:
        author = "Elastic Security"
        id = "08bfc26b-efda-49b4-b685-57edca8b9d18"
        fingerprint = "9c0c4a5bce63c9d99d53813f7250b3ccc395cb99eaebb8c016f8c040fbfa4ea7"
        creation_date = "2024-05-29"
        last_modified = "2024-06-12"
        threat_name = "Windows.Trojan.SolarMarker"
        reference_sample = "c1a6d2d78cc50f080f1fe4cadc6043027bf201d194f2b73625ce3664433a3966"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 07 09 91 61 D2 9C 09 20 C8 00 00 00 5D 16 FE 01 16 FE 01 13 }
        $a2 = { 91 07 08 91 61 D2 9C 08 20 C8 00 00 00 5D 16 FE 01 16 FE 01 }
        $a3 = { 06 08 06 08 91 07 08 91 61 D2 9C 08 20 C8 00 00 00 5D 16 FE }
    condition:
        any of them
}

