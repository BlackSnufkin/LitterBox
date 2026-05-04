rule Linux_Trojan_Chinaz_a2140ca1 {
    meta:
        author = "Elastic Security"
        id = "a2140ca1-0a72-4dcb-bf7c-2f51e84a996b"
        fingerprint = "ac620f3617ea448b2ad62f06490c37200fa0af8a6fe75a6a2a294a7b5b4a634a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Chinaz"
        reference_sample = "7c44c2ca77ef7a62446f6266a757817a6c9af5e010a219a43a1905e2bc5725b0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 53 8B 74 24 0C 8B 5C 24 10 8D 74 26 00 89 C2 89 C1 C1 FA 03 83 }
    condition:
        all of them
}

