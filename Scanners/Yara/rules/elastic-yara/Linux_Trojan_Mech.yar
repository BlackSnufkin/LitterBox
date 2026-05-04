rule Linux_Trojan_Mech_d30ec0a0 {
    meta:
        author = "Elastic Security"
        id = "d30ec0a0-3fd6-4d83-ad29-9d45704bc8ce"
        fingerprint = "061e9f1aade510132674d87ab5981e5b6b0ae3a2782a97d8cc6c2be7b26c6454"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mech"
        reference_sample = "710d1a0a8c7eecc6d793933c8a97cec66d284b3687efee7655a2dc31d15c0593"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6E 63 20 2D 20 4C 69 6E 75 78 20 32 2E 32 2E 31 }
    condition:
        all of them
}

