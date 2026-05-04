rule Linux_Cryptominer_Presenoker_3bb5533d {
    meta:
        author = "Elastic Security"
        id = "3bb5533d-4722-4801-9fbb-dd2c916cffc6"
        fingerprint = "a3005a07901953ae8def7bd9d9ec96874da0a8aedbebde536504abed9d4191fd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Presenoker"
        reference_sample = "bbc155c610c7aa439f98e32f97895d7eeaef06dab7cca05a5179b0eb3ba3cc00"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 47 10 74 72 F3 0F 6F 00 66 0F 7E C2 0F 29 04 24 85 D2 F3 0F 6F }
    condition:
        all of them
}

