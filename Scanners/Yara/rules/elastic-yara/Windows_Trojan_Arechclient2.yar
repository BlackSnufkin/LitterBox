rule Windows_Trojan_Arechclient2_b6ea1c83 {
    meta:
        author = "Elastic Security"
        id = "b6ea1c83-cb39-4de9-a1e9-c2b3287612e1"
        fingerprint = "b86c66efad907cf421555959d3a8dae9e54a1c798101f7cc87211d9c5b3ee2fc"
        creation_date = "2025-06-09"
        last_modified = "2025-06-13"
        threat_name = "Windows.Trojan.Arechclient2"
        reference_sample = "c4b907418319f5066d5358640aac38ff53c46c8250aeacaa92987e163cb6b224"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 65 73 00 53 63 61 6E 6E 65 64 57 61 6C 6C 65 74 73 00 4E 6F 72 64 41 63 63 6F 75 6E 74 73 00 4F 70 65 6E 00 50 72 6F 74 6F 6E 00 4D 65 73 73 61 }
        $b = { 73 65 74 5F 53 63 61 6E 56 50 4E 00 67 65 74 5F 53 63 61 6E 53 74 65 61 6D 00 73 65 74 5F 53 63 61 6E 53 74 65 61 6D 00 67 65 74 5F 53 63 61 6E }
    condition:
        any of them
}

