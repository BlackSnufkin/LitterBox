rule Linux_Cryptominer_Casdet_5d0d33be {
    meta:
        author = "Elastic Security"
        id = "5d0d33be-e53e-4188-9957-e1af2a802867"
        fingerprint = "2d584f6815093d37bd45a01146034d910b95be51462f01f0d4fc4a70881dfda6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Casdet"
        reference_sample = "4b09115c876a8b610e1941c768100e03c963c76b250fdd5b12a74253ef9e5fb6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C3 EB 05 48 89 C3 EB CF 48 8B BC 24 A0 00 00 00 48 85 FF 74 D7 48 }
    condition:
        all of them
}

