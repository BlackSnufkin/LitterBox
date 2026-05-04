rule Linux_Cryptominer_Minertr_9901e275 {
    meta:
        author = "Elastic Security"
        id = "9901e275-3053-47ea-8c36-6c9271923b64"
        fingerprint = "f27e404d545f3876963fd6174c4235a4fe4f69d53fe30a2d29df9dad6d97b7f7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Minertr"
        reference_sample = "f77246a93782fd8ee40f12659f41fccc5012a429a8600f332c67a7c2669e4e8f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 56 41 55 41 54 55 53 48 83 EC 78 48 89 3C 24 89 F3 89 74 }
    condition:
        all of them
}

