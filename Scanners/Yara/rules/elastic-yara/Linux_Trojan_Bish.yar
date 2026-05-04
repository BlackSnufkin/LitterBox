rule Linux_Trojan_Bish_974b4b47 {
    meta:
        author = "Elastic Security"
        id = "974b4b47-38cf-4460-8ff3-e066e5c8a5fc"
        fingerprint = "8858f99934e367b7489d60bfaa74ab57e2ae507a8c06fb29693197792f6f5069"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Bish"
        reference_sample = "9171fd2bbe182f0a3cd35937f3ee0076c9358f52f5bc047498dd9e233ae11757"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 31 C0 31 DB 31 C9 B0 17 CD 80 31 C0 50 68 6E }
    condition:
        all of them
}

