rule Linux_Trojan_Meterpreter_a82f5d21 {
    meta:
        author = "Elastic Security"
        id = "a82f5d21-3b01-4a05-a34a-6985c1f3b460"
        fingerprint = "b0adb928731dc489a615fa86e46cc19de05e251eef2e02eb02f478ed1ca01ec5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Meterpreter"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 02 74 22 77 08 66 83 F8 01 74 20 EB 24 66 83 F8 03 74 0C 66 83 }
    condition:
        all of them
}

rule Linux_Trojan_Meterpreter_383c6708 {
    meta:
        author = "Elastic Security"
        id = "383c6708-0861-4089-93c3-4320bc1e7cfc"
        fingerprint = "6e9da04c91b5846b3b1109f9d907d9afa917fb7dfe9f77780e745d17b799b540"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Meterpreter"
        reference_sample = "d9d607f0bbc101f7f6dc0f16328bdd8f6ddb8ae83107b7eee34e1cc02072cb15"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A B2 07 0F 05 48 96 48 }
    condition:
        all of them
}

rule Linux_Trojan_Meterpreter_621054fe {
    meta:
        author = "Elastic Security"
        id = "621054fe-bbdf-445c-a503-ccba82b88243"
        fingerprint = "13cb03783b1d5f14cadfaa9b938646d5edb30ea83702991a81cc4ca82e4637dc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Meterpreter"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 28 85 D2 75 0A 8B 50 2C 83 C8 FF 85 D2 74 03 8B 42 64 5D C3 55 }
    condition:
        all of them
}

rule Linux_Trojan_Meterpreter_1bda891e {
    meta:
        author = "Elastic Security"
        id = "1bda891e-a031-4254-9d0b-dc590023d436"
        fingerprint = "fc3f5afb9b90bbf3b61f144f90b02ff712f60fbf62fb0c79c5eaa808627aa0a1"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Meterpreter"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 11 62 08 F2 0F 5E D0 F2 0F 58 CB F2 0F 11 5A 10 F2 44 0F 5E C0 F2 0F }
    condition:
        all of them
}

