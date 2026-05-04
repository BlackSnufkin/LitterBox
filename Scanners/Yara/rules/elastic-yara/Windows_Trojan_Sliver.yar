rule Windows_Trojan_Sliver_46525b49 {
    meta:
        author = "Elastic Security"
        id = "46525b49-f426-4ecb-9bd6-36752f0461e9"
        fingerprint = "104382f222b754b3de423803ac7be1d6fbdd9cbd11c855774d1ecb1ee73cb6c0"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Sliver"
        reference_sample = "ecce5071c28940a1098aca3124b3f82e0630c4453f4f32e1b91576aac357ac9c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { B6 54 0C 48 0F B6 74 0C 38 31 D6 40 88 74 0C 38 48 FF C1 48 83 }
        $a2 = { 42 18 4C 8B 4A 20 48 8B 52 28 48 39 D9 73 51 48 89 94 24 C0 00 }
    condition:
        all of them
}

rule Windows_Trojan_Sliver_c9cae357 {
    meta:
        author = "Elastic Security"
        id = "c9cae357-9270-4871-8fad-d9c43dcab644"
        fingerprint = "5366540c4a4f4a502b550f5397f3b53e3bc909cbc0cb82a2091cabb19bc135aa"
        creation_date = "2023-05-10"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Sliver"
        reference_sample = "27210d8d6e16c492c2ee61a59d39c461312f5563221ad4a0917d4e93b699418e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { B1 F9 3C 0A 68 0F B4 B5 B5 B5 21 B2 38 23 29 D8 6F 83 EC 68 51 8E }
    condition:
        all of them
}

rule Windows_Trojan_Sliver_1dd6d9c2 {
    meta:
        author = "Elastic Security"
        id = "1dd6d9c2-026e-4140-b804-b56e07c72ac2"
        fingerprint = "fb676adf8b9d10d1e151bfb2a6a7e132cff4e55c20f454201a4ece492902fc35"
        creation_date = "2023-05-10"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Sliver"
        reference_sample = "dc508a3e9ea093200acfc1ceebebb2b56686f4764fd8c94ab8c58eec7ee85c8b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { B7 11 49 89 DB C1 EB 10 41 01 DA 66 45 89 11 4C 89 DB EB B6 4D 8D }
        $a2 = { 36 2E 33 20 62 75 69 6C 48 39 }
    condition:
        all of them
}

