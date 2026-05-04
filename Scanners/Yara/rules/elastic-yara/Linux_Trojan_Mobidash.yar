rule Linux_Trojan_Mobidash_52a15a93 {
    meta:
        author = "Elastic Security"
        id = "52a15a93-0574-44bb-83c9-793558432553"
        fingerprint = "a7ceff3bbd61929ab000d18ffdf2e8d1753ecea123e26cd626e3af64341effe6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 89 CE 41 55 41 54 49 89 F4 55 48 89 D5 53 48 89 FB 48 8B 07 FF 90 F8 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_d0ad9c82 {
    meta:
        author = "Elastic Security"
        id = "d0ad9c82-718f-43d1-a764-9be83893f9b8"
        fingerprint = "ef6b2f9383c137eb4adfe0a6322a0e5d71cb4a5712f1be26fe687144933cbbc8"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 54 49 89 CC 55 48 89 D5 53 48 89 FB 48 8D 64 24 F8 48 8B 07 FF 90 F8 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_e2c89606 {
    meta:
        author = "Elastic Security"
        id = "e2c89606-511c-403a-a4eb-d18dc7aca444"
        fingerprint = "91c51f6af18389f2efb0032e0b775df68f34b66795c05623dccb67266c04214b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 13 49 89 C7 4C 89 E6 48 89 DF FF 92 B8 00 00 00 31 C9 4C 89 FA 4C }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_82b4e3f3 {
    meta:
        author = "Elastic Security"
        id = "82b4e3f3-a9ba-477c-8eef-6010767be52f"
        fingerprint = "a01f5ba8b3e8e82ff46cb748fd90a103009318a25f8532fb014722c96f0392db"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C6 74 2E 89 44 24 0C 8B 44 24 24 C7 44 24 08 01 00 00 00 89 7C }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_601352dc {
    meta:
        author = "Elastic Security"
        id = "601352dc-13b6-4c3f-a013-c54a50e46820"
        fingerprint = "acfca9259360641018d2bf9ba454fd5b65224361933557e007ab5cfb12186cd7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "5714e130075f4780e025fb3810f58a63e618659ac34d12abe211a1b6f2f80269"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F6 74 14 48 8B BC 24 D0 00 00 00 48 8B 07 48 8B 80 B8 00 00 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_ddca1181 {
    meta:
        author = "Elastic Security"
        id = "ddca1181-91ca-4e5d-953f-be85838d3cb9"
        fingerprint = "c8374ff2a85f90f153bcd2451109a65d3757eb7cef21abef69f7c6a4f214b051"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 84 C0 75 1E 8B 44 24 2C 89 7C 24 04 89 34 24 89 44 24 0C 8B 44 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_65e666c0 {
    meta:
        author = "Elastic Security"
        id = "65e666c0-4eb7-4411-8743-053b6c0ec1d6"
        fingerprint = "92b7de293a7e368d0e92a6e2061e9277e7b285851322357808a04f8c203b20d0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "19f9b5382d3e8e604be321aefd47cb72c2337a170403613b853307c266d065dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4C 8B 44 24 08 48 89 DF 48 8B 14 24 48 8D 64 24 18 5B 4C 89 E6 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_494d5b0f {
    meta:
        author = "Elastic Security"
        id = "494d5b0f-09c7-4fcb-90e9-1efc57c45082"
        fingerprint = "e3316257592dc9654a5e63cf33c862ea1298af7a893e9175e1a15c7aaa595f6a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "7e08df5279f4d22f1f27553946b0dadd60bb8242d522a8dceb45ab7636433c2f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 18 00 00 00 40 04 00 00 01 5B 00 00 00 3A 00 00 00 54 04 00 00 05 A1 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_bb4f7f39 {
    meta:
        author = "Elastic Security"
        id = "bb4f7f39-1f1c-4a2d-a480-3e1d2b6967b7"
        fingerprint = "b7e96ff17a19ffcbfc87cdba3f86216271ff01c460ff7564f6af6b40c21a530b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 75 1F 48 8D 64 24 08 48 89 DF 5B 48 89 EA 4C 89 E1 4C 89 EE 5D }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_8679e1cb {
    meta:
        author = "Elastic Security"
        id = "8679e1cb-407e-4554-8ef5-ece5110735c6"
        fingerprint = "7e517bf9e036410acf696c85bd39c720234b64aab8c5b329920a64f910c72c92"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 1C 89 F0 5B 5E 5F 5D C3 8D 76 00 8B 44 24 34 83 C6 01 8D 7C }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_29b86e6a {
    meta:
        author = "Elastic Security"
        id = "29b86e6a-fcad-49ac-ae78-ce28987f7363"
        fingerprint = "5d7d930f39e435fc22921571fe96db912eed79ec630d4ed60da6f007073b7362"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2E 10 73 2E 10 02 47 2E 10 56 2E 10 5C 2E 10 4E 2E 10 49 2E 10 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_e3086563 {
    meta:
        author = "Elastic Security"
        id = "e3086563-346d-43f1-89eb-42693dc17195"
        fingerprint = "8fc223f3850994479a70358da66fb31b610e00c9cbc3a94fd7323780383d738e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 48 8B 4C 24 08 49 8B 55 00 48 39 D1 75 16 48 8D 64 24 10 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_2f114992 {
    meta:
        author = "Elastic Security"
        id = "2f114992-36a7-430c-8bd9-5661814d95a8"
        fingerprint = "2371fc5ba1e279a77496328d3a39342408609f04f1a8947e84e734d28d874416"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { DF 4C 89 F6 48 8B 80 B8 00 00 00 48 8D 64 24 58 5B 5D 41 5C }
    condition:
        all of them
}

