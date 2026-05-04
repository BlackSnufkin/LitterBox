rule Linux_Trojan_Snessik_d166f98c {
    meta:
        author = "Elastic Security"
        id = "d166f98c-0fa3-4a1b-a6d2-7fbe4e338fc7"
        fingerprint = "6247d59326ea71426862e1b242c7354ee369fbe6ea766e40736e2f5a6410c8d7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Snessik"
        reference_sample = "f3ececc2edfff2f92d80ed3a5140af55b6bebf7cae8642a0d46843162eeddddd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D2 74 3B 83 CA FF F0 0F C1 57 10 85 D2 7F 9F 48 8D 74 24 2E 89 44 }
    condition:
        all of them
}

rule Linux_Trojan_Snessik_e435a79c {
    meta:
        author = "Elastic Security"
        id = "e435a79c-4b8e-42de-8d78-51b684eba178"
        fingerprint = "bd9f81d03812e49323b86b2ea59bf5f08021d0b43f7629eb4d59e75eccb7dcf1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Snessik"
        reference_sample = "e24749b07f824a4839b462ec4e086a4064b29069e7224c24564e2ad7028d5d60"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C6 75 38 31 C0 48 8B 5C 24 68 48 8B 6C 24 70 4C 8B 64 24 78 4C 8B AC 24 80 00 }
    condition:
        all of them
}

