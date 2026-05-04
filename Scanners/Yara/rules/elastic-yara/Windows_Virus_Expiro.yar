rule Windows_Virus_Expiro_84e99ff0 {
    meta:
        author = "Elastic Security"
        id = "84e99ff0-bff3-4a9c-93fb-504a32cbc44d"
        fingerprint = "843182cbbf7ff65699001f074972d584c65bdb1e1d76210b44cf6ba06830253c"
        creation_date = "2023-09-26"
        last_modified = "2023-11-02"
        threat_name = "Windows.Virus.Expiro"
        reference_sample = "47107836ead700bddbe9e8a0c016b5b1443c785442b2addbb50a70445779bad7"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 50 51 52 53 55 56 57 E8 00 00 00 00 5B 81 EB ?? ?? ?? 00 BA 00 00 00 00 53 81 }
        $a2 = { 81 C2 00 04 00 00 81 C3 00 04 00 00 }
    condition:
        all of them
}

