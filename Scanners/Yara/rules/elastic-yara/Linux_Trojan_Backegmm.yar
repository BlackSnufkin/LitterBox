rule Linux_Trojan_Backegmm_b59712e6 {
    meta:
        author = "Elastic Security"
        id = "b59712e6-d14d-4a57-a3d6-2dc323bf840d"
        fingerprint = "61b2f0c7cb98439b05776edeaf06b114d364119ebe733d924158792110c5e21c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Backegmm"
        reference_sample = "d6c8e15cb65102b442b7ee42186c58fa69cd0cb68f4fd47eb5ad23763371e0be"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 69 73 74 65 6E 00 66 6F 72 6B 00 73 70 72 69 6E 74 66 00 68 }
    condition:
        all of them
}

