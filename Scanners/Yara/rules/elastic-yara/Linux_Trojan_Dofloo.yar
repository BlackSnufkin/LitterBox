rule Linux_Trojan_Dofloo_be1973ed {
    meta:
        author = "Elastic Security"
        id = "be1973ed-a0ee-41ca-a752-fb5f990e2096"
        fingerprint = "f032f072fd5da9ec4d8d3953bea0f2a236219b99ecfa67e3fac44f2e73f33e9c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dofloo"
        reference_sample = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { A8 8B 45 A8 89 45 A4 83 7D A4 00 79 04 83 45 A4 03 8B 45 A4 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Dofloo_1d057993 {
    meta:
        author = "Elastic Security"
        id = "1d057993-0a46-4014-8ab6-aa9e9d93dfa1"
        fingerprint = "c4bb948b85777b1f5df89fafba0674bc245bbda1962c576abaf0752f49c747d0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dofloo"
        reference_sample = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 88 45 DB 83 EC 04 8B 45 F8 83 C0 03 89 45 D4 8B 45 D4 89 }
    condition:
        all of them
}

rule Linux_Trojan_Dofloo_29c12775 {
    meta:
        author = "Elastic Security"
        id = "29c12775-b7e5-417d-9789-90b9bd4529dd"
        fingerprint = "fbf49f0904e22c4d788f151096f9b1d80aa8c739b31705e6046d17029a6a7a4f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dofloo"
        reference_sample = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 2F 7E 49 00 64 80 49 00 34 7F 49 00 04 7F 49 00 24 80 49 }
    condition:
        all of them
}

