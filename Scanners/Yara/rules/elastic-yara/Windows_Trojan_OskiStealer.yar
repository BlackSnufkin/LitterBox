rule Windows_Trojan_OskiStealer_a158b1e3 {
    meta:
        author = "Elastic Security"
        id = "a158b1e3-21b7-4009-9646-6bee9bde98ad"
        fingerprint = "3996a89d37494b118654f3713393f415c662850a5a76afa00e83f9611aee3221"
        creation_date = "2022-03-21"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.OskiStealer"
        reference_sample = "568cd515c9a3bce7ef21520761b02cbfc95d8884d5b2dc38fc352af92356c694"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "\"os_crypt\":{\"encrypted_key\":\"" ascii fullword
        $a2 = "%s / %s" ascii fullword
        $a3 = "outlook.txt" ascii fullword
        $a4 = "GLoX6gmCFw==" ascii fullword
        $a5 = "KaoQpEzKSjGm8Q==" ascii fullword
    condition:
        all of them
}

