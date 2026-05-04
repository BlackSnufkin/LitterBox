rule Windows_Trojan_Merlin_e8ecb3be {
    meta:
        author = "Elastic Security"
        id = "e8ecb3be-edba-4617-b4df-9d5b6275d310"
        fingerprint = "54e03337930d74568a91e797cfda3b7bfbce3aad29be2543ed58c51728d8e185"
        creation_date = "2022-01-05"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Merlin"
        reference_sample = "768c120e63d3960a0842dcc538749955ab7caabaeaf3682f6d1e30666aac65a8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { AF F0 4C 01 F1 4C 8B B4 24 A8 00 00 00 4D 0F AF F4 4C 01 F1 4C 8B B4 24 B0 00 }
    condition:
        all of them
}

