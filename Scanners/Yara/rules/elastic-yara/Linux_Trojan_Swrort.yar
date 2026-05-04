rule Linux_Trojan_Swrort_5ad1a4f9 {
    meta:
        author = "Elastic Security"
        id = "5ad1a4f9-bfe5-4e5f-94e9-4983c93a1c1f"
        fingerprint = "a91458dd4bcd082506c554ca8479e1b0d23598e0e9a0e44ae1afb2651ce38dce"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Swrort"
        reference_sample = "fa5695c355a6dc1f368a4b36a45e8f18958dacdbe0eac80c618fbec976bac8fe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 53 57 68 B7 E9 38 FF FF D5 53 53 57 68 74 EC 3B E1 FF D5 57 }
    condition:
        all of them
}

rule Linux_Trojan_Swrort_4cb5b116 {
    meta:
        author = "Elastic Security"
        id = "4cb5b116-5e90-4e5f-a62f-bfe616cab5db"
        fingerprint = "cb783f69b4074264a75894dd85459529a172404a6901a1f5753a2f9197bfca58"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Swrort"
        reference_sample = "703c16d4fcc6f815f540d50d8408ea00b4cf8060cc5f6f3ba21be047e32758e0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 6A 04 6A 10 89 E1 6A 00 }
    condition:
        all of them
}

rule Linux_Trojan_Swrort_22c2d6b6 {
    meta:
        author = "Elastic Security"
        id = "22c2d6b6-d100-4310-87c4-3912a86bdd40"
        fingerprint = "d2b16da002cb708cb82f8b96c7d31f15c9afca69e89502b1970758294e91f9a4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Swrort"
        reference_sample = "6df073767f48dd79f98e60aa1079f3ab0b89e4f13eedc1af3c2c073e5e235bbc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 31 DB F7 E3 53 43 53 6A 02 89 E1 B0 66 CD 80 51 6A 04 54 6A 02 }
    condition:
        all of them
}

