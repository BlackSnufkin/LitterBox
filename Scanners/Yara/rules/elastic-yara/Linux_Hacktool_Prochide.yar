rule Linux_Hacktool_Prochide_7333221a {
    meta:
        author = "Elastic Security"
        id = "7333221a-b3dc-4b26-8ec7-7e4f5405e228"
        fingerprint = "e3aa99d48a8554dfaf9f7d947170e6e169b99bf5b6347d4832181e80cc2845cf"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Prochide"
        reference_sample = "fad956a6a38abac8a8a0f14cc50f473ec6fc1c9fd204e235b89523183931090b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF FF 83 BD 9C FC FF FF FF 75 14 BF 7F 22 40 00 }
    condition:
        all of them
}

