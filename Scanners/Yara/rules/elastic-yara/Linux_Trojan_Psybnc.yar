rule Linux_Trojan_Psybnc_563ecb11 {
    meta:
        author = "Elastic Security"
        id = "563ecb11-e215-411f-8583-7cb7b2956252"
        fingerprint = "1e7a2a6240d6f7396505cc2203c03d4ae93a7ef0c0c956cef7a390b4303a2cbe"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Psybnc"
        reference_sample = "f77216b169e8d12f22ef84e625159f3a51346c2b6777a1fcfb71268d17b06d39"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5F 65 6E 00 6B 6F 5F 65 6E 00 72 75 5F 65 6E 00 65 73 5F 65 6E 00 44 }
    condition:
        all of them
}

rule Linux_Trojan_Psybnc_ab3396d5 {
    meta:
        author = "Elastic Security"
        id = "ab3396d5-388b-4730-9a55-581c327a2769"
        fingerprint = "1180e02d3516466457f48dc614611a6949a4bf21f6a294f6384892db30dc4171"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Psybnc"
        reference_sample = "c5ec84e7cc891af25d6319abb07b1cedd90b04cbb6c8656c60bcb07e60f0b620"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 53 54 00 55 53 45 52 4F 4E 00 30 00 50 25 64 00 58 30 31 00 }
    condition:
        all of them
}

rule Linux_Trojan_Psybnc_f07357f1 {
    meta:
        author = "Elastic Security"
        id = "f07357f1-1a92-4bd7-a43d-7a75fb90ac83"
        fingerprint = "f0f1008fec444ce25d80f9878a04d9ebe9a76f792f4be8747292ee7b133ea05c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Psybnc"
        reference_sample = "f77216b169e8d12f22ef84e625159f3a51346c2b6777a1fcfb71268d17b06d39"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F7 EA 89 D0 C1 F8 02 89 CF C1 FF 1F 29 F8 8D 04 80 01 C0 29 C1 8D }
    condition:
        all of them
}

