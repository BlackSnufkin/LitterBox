rule MacOS_Virus_Maxofferdeal_53df500f {
    meta:
        author = "Elastic Security"
        id = "53df500f-3add-4d3d-aec3-35b7b5aa5b35"
        fingerprint = "2f41de7b8e55ef8db39bf84c0f01f8d34d67b087769b84381f2ccc3778e13b08"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Virus.Maxofferdeal"
        reference_sample = "ecd62ef880da057726ca55c6826ce4e1584ec6fc3afaabed7f66154fc39ffef8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 AC AD AE A9 BD A4 BC 97 }
    condition:
        all of them
}

rule MacOS_Virus_Maxofferdeal_f4681eba {
    meta:
        author = "Elastic Security"
        id = "f4681eba-20f5-4e92-9f99-00cd57412c45"
        fingerprint = "b6663c326e9504510b804bd9ff0e8ace5d98826af2bb2fa2429b37171b7f399d"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Virus.Maxofferdeal"
        reference_sample = "ecd62ef880da057726ca55c6826ce4e1584ec6fc3afaabed7f66154fc39ffef8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { BA A4 C8 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 AC AD AE A9 BD A4 BC 97 }
    condition:
        all of them
}

rule MacOS_Virus_Maxofferdeal_4091e373 {
    meta:
        author = "Elastic Security"
        id = "4091e373-c3a9-41c8-a1d8-3a77585ff850"
        fingerprint = "3d8e7db6c39286d9626c6be8bfb5da177a6a4f8ffcec83975a644aaac164a8c7"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Virus.Maxofferdeal"
        reference_sample = "c38c4bdd3c1fa16fd32db06d44d0db1b25bb099462f8d2936dbdd42af325b37c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { B8 F2 E7 E7 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 8B 8E 8A BD A6 AC A4 }
    condition:
        all of them
}

rule MacOS_Virus_Maxofferdeal_20a0091e {
    meta:
        author = "Elastic Security"
        id = "20a0091e-a3ef-4a13-ba92-700f3583e06d"
        fingerprint = "1629b34b424816040066122592e56e317b204f3d5de2f5e7f68114c7a48d99cb"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Virus.Maxofferdeal"
        reference_sample = "b00a61c908cd06dbc26bee059ba290e7ce2ad6b66c453ea272c7287ffa29c5ab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { F2 E7 E7 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 A0 BC BC B8 F2 E7 E7 BF }
    condition:
        all of them
}

