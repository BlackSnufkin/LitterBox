rule Windows_Trojan_WikiLoader_c57f3f88 {
    meta:
        author = "Elastic Security"
        id = "c57f3f88-0d2c-41a6-b2f9-839b1f1e1193"
        fingerprint = "a3802da23431fcbc890a5164d6acdbf29ec29bf1a82d4b862495edd8ae642d52"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Trojan.WikiLoader"
        reference_sample = "0f71b1805d7feb6830b856c5a5328d3a132af4c37fcd747d82beb0f61c77f6f5"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 81 EC 08 01 00 00 48 89 CB 48 31 C0 48 89 E9 48 29 E1 48 89 E7 F3 AA 48 89 D9 48 89 4D 80 48 89 95 78 FF FF FF 4C 89 45 C0 4C 89 4D 88 4D 89 D4 4D 89 DD 4C 89 65 C8 49 83 ED 10 4C 89 6D 98 }
    condition:
        all of them
}

rule Windows_Trojan_WikiLoader_99681f1c {
    meta:
        author = "Elastic Security"
        id = "99681f1c-8b32-4cb0-ab6b-640b316e587a"
        fingerprint = "1cd978adc6cbd36a5738fb4c26a2ba4aaa8e69a035bd2618ef2175b3bb2dc4b6"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Trojan.WikiLoader"
        reference_sample = "0b02cfe16ac73f2e7dc52eaf3b93279b7d02b3d64d061782dfed0c55ab621a8e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 83 EC 08 48 89 E0 4C 89 20 48 83 EC 08 48 89 E0 4C 89 28 48 83 EC 08 48 89 E0 4C 89 30 48 83 EC 08 48 89 E0 4C 89 38 48 89 E5 48 83 EC 08 48 83 EC 60 48 89 CB 48 31 C0 48 89 E9 48 29 E1 48 }
    condition:
        all of them
}

