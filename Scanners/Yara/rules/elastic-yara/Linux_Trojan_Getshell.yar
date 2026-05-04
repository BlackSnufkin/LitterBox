rule Linux_Trojan_Getshell_98d002bf {
    meta:
        author = "Elastic Security"
        id = "98d002bf-63b7-4d11-98ef-c3127e68d59c"
        fingerprint = "b7bfec0a3cfc05b87fefac6b10673491b611400edacf9519cbcc1a71842e9fa3"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Getshell"
        reference_sample = "97b7650ab083f7ba23417e6d5d9c1d133b9158e2c10427d1f1e50dfe6c0e7541"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B2 6A B0 03 CD 80 85 C0 78 02 FF E1 B8 01 00 00 00 BB 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Getshell_213d4d69 {
    meta:
        author = "Elastic Security"
        id = "213d4d69-5660-468d-a98c-ff3eef604b1e"
        fingerprint = "60e385e4c5eb189785bc14d39bf8a22c179e4be861ce3453fbcf4d367fc87c90"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Getshell"
        reference = "05fc4dcce9e9e1e627ebf051a190bd1f73bc83d876c78c6b3d86fc97b0dfd8e8"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EC 01 00 00 00 EB 3C 8B 45 EC 48 98 48 C1 E0 03 48 03 45 D0 48 }
    condition:
        all of them
}

rule Linux_Trojan_Getshell_3cf5480b {
    meta:
        author = "Elastic Security"
        id = "3cf5480b-bb21-4a6e-a078-4b145d22c79f"
        fingerprint = "3ef0817445c54994d5a6792ec0e6c93f8a51689030b368eb482f5ffab4761dd2"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Getshell"
        reference = "0e41c0d6286fb7cd3288892286548eaebf67c16f1a50a69924f39127eb73ff38"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B2 24 B0 03 CD 80 85 C0 78 02 FF E1 B8 01 00 00 00 BB 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Getshell_8a79b859 {
    meta:
        author = "Elastic Security"
        id = "8a79b859-654c-4082-8cfc-61a143671457"
        fingerprint = "5a95d1df94791c8484d783da975bec984fb11653d1f81f6397efd734a042272b"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Getshell"
        reference = "1154ba394176730e51c7c7094ff3274e9f68aaa2ed323040a94e1c6f7fb976a2"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0A 00 89 E1 6A 1C 51 56 89 E1 43 6A 66 58 CD 80 B0 66 B3 04 }
    condition:
        all of them
}

