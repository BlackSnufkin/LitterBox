rule Linux_Cryptominer_Loudminer_581f57a9 {
    meta:
        author = "Elastic Security"
        id = "581f57a9-36e0-4b95-9a1e-837bdd4aceab"
        fingerprint = "1013e6e11ea2a30ecf9226ea2618a59fb08588cdc893053430e969fbdf6eb675"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Loudminer"
        reference_sample = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 44 24 08 48 8B 70 20 48 8B 3B 48 83 C3 08 48 89 EA 48 8B 07 FF }
    condition:
        all of them
}

rule Linux_Cryptominer_Loudminer_f2298a50 {
    meta:
        author = "Elastic Security"
        id = "f2298a50-7bd4-43d8-ac84-b36489405f2e"
        fingerprint = "8eafc1c995c0efb81d9ce6bcc107b102551371f3fb8efdf8261ce32631947e03"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Loudminer"
        reference_sample = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B6 04 07 41 8D 40 D0 3C 09 76 AD 41 8D 40 9F 3C 05 76 A1 41 8D }
    condition:
        all of them
}

rule Linux_Cryptominer_Loudminer_851fc7aa {
    meta:
        author = "Elastic Security"
        id = "851fc7aa-6514-4f47-b6b5-a1e730b5d460"
        fingerprint = "e4d78229c1877a023802d7d99eca48bffc55d986af436c8a1df7c6c4e5e435ba"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Loudminer"
        reference_sample = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 49 8B 45 00 4C 8B 40 08 49 8D 78 18 49 89 FA 49 29 D2 49 01 C2 4C }
    condition:
        all of them
}

