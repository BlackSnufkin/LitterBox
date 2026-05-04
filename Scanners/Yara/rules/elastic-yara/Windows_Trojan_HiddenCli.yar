rule Windows_Trojan_HiddenCli_a9aa62d1 {
    meta:
        author = "Elastic Security"
        id = "a9aa62d1-f131-42c4-a62a-0172db697996"
        fingerprint = "f546cfc4530294a778db94e5295227bb61e39af54526605da7f8224811ba5a3c"
        creation_date = "2025-10-02"
        last_modified = "2025-10-13"
        threat_name = "Windows.Trojan.HiddenCli"
        reference_sample = "913431f1d36ee843886bb052bfc89c0e5db903c673b5e6894c49aabc19f1e2fc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $b_1 = { 48 8B 0A 48 8D 45 E7 33 FF 4C 8D 45 EB 48 89 7C 24 38 BA 04 20 22 00 48 89 44 24 30 48 8D 45 27 }
        $unicode_1 = { 43 00 6F 00 6D 00 6D 00 61 00 6E 00 64 00 20 00 27 00 73 00 74 00 61 00 74 00 65 00 27 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6C 00 00 00 }
    condition:
        1 of them
}

