rule Linux_Cryptominer_Bulz_2aa8fbb5 {
    meta:
        author = "Elastic Security"
        id = "2aa8fbb5-b392-49fc-8f0f-12cd06d534e2"
        fingerprint = "c8fbeae6cf935fe629c37abc4fdcda2c80c1b19fc8b6185a58decead781e1321"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Bulz"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FE D7 C5 D9 72 F2 09 C5 E9 72 D2 17 C5 E9 EF D4 C5 E9 EF D6 C5 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Bulz_0998f811 {
    meta:
        author = "Elastic Security"
        id = "0998f811-7be3-4d46-9dcb-1e8a0f19bab5"
        fingerprint = "c8a83bc305998cb6256b004e9d8ce6d5d1618b107e42be139b73807462b53c31"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Bulz"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 79 70 E4 39 C5 F9 70 C9 4E C5 91 72 F0 12 C5 F9 72 D0 0E C5 91 }
    condition:
        all of them
}

