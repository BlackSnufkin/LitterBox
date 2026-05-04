rule Linux_Trojan_Nuker_12f26779 {
    meta:
        author = "Elastic Security"
        id = "12f26779-bda5-45b1-925f-75c620d7d840"
        fingerprint = "9093a96321ad912f2bb953cce460d0945c1c4e5aacd8431f343498203b85bb9b"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Nuker"
        reference_sample = "440105a62c75dea5575a1660fe217c9104dc19fb5a9238707fe40803715392bf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C4 18 89 45 D8 83 7D D8 FF 75 17 68 ?? ?? 04 08 }
    condition:
        all of them
}

