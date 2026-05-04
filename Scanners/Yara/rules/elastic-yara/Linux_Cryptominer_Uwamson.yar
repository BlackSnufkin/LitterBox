rule Linux_Cryptominer_Uwamson_c42fd06d {
    meta:
        author = "Elastic Security"
        id = "c42fd06d-b9ab-4f1f-bb59-e7b49355115c"
        fingerprint = "dac171e66289e2222cd631d616f31829f31dfeeffb34f0e1dcdd687d294f117c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Uwamson"
        reference_sample = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F0 4C 89 F3 48 8B 34 24 48 C1 E0 04 48 C1 E3 07 48 8B 7C 24 10 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Uwamson_d08b1d2e {
    meta:
        author = "Elastic Security"
        id = "d08b1d2e-cbd5-420e-8f36-22b9efb5f12c"
        fingerprint = "1e55dc81a44af9c15b7a803e72681b5c24030d34705219f83ca4779fd885098c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Uwamson"
        reference_sample = "4f7ad24b53b8e255710e4080d55f797564aa8c270bf100129bdbe52a29906b78"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4F F8 49 8D 7D 18 89 D9 49 83 C5 20 48 89 FE 41 83 E1 0F 4D 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Uwamson_0797de34 {
    meta:
        author = "Elastic Security"
        id = "0797de34-9181-4f28-a4b0-eafa67e20b41"
        fingerprint = "b6a210c23f09ffa0114f12aa741be50f234b8798a3275ac300aa17da29b8727c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Uwamson"
        reference_sample = "e4699e35ce8091f97decbeebff63d7fa8c868172a79f9d9d52b6778c3faab8f2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 43 20 48 B9 AB AA AA AA AA AA AA AA 88 44 24 30 8B 43 24 89 44 }
    condition:
        all of them
}

rule Linux_Cryptominer_Uwamson_41e36585 {
    meta:
        author = "Elastic Security"
        id = "41e36585-0ef1-4896-a887-dac437c716a5"
        fingerprint = "ad2d4a46b9378c09b1aef0f2bf67a990b3bacaba65a5b8c55c2edb0c9a63470d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Uwamson"
        reference_sample = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 03 48 C1 FF 03 4F 8D 44 40 FD 48 0F AF FE 49 01 F8 4C 01 C2 4C }
    condition:
        all of them
}

