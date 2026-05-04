rule Linux_Trojan_Ddostf_e4874cd4 {
    meta:
        author = "Elastic Security"
        id = "e4874cd4-50e3-4a4c-b14c-976e29aaaaae"
        fingerprint = "dfbf7476794611718a1cd2c837560423e3a6c8b454a5d9eecb9c6f9d31d01889"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ddostf"
        reference_sample = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E4 01 8B 45 F0 2B 45 F4 89 C2 8B 45 E4 39 C2 73 82 8B 45 EC }
    condition:
        all of them
}

rule Linux_Trojan_Ddostf_32c35334 {
    meta:
        author = "Elastic Security"
        id = "32c35334-f264-4509-b5c4-b07e477bd07d"
        fingerprint = "f71d1e9188f67147de8808d65374b4e34915e9d60ff475f7fc519c8918c75724"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ddostf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0E 18 41 0E 1C 41 0E 20 48 0E 10 00 4C 00 00 00 64 4B 00 00 }
    condition:
        all of them
}

rule Linux_Trojan_Ddostf_6dc1caab {
    meta:
        author = "Elastic Security"
        id = "6dc1caab-be84-4f27-a059-2acffc20ca2c"
        fingerprint = "43bcb29d92e0ed2dfd0ff182991864f8efabd16a0f87e8c3bb453b47bd8e272b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ddostf"
        reference_sample = "f4587bd45e57d4106ebe502d2eaa1d97fd68613095234038d67490e74c62ba70"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FC 01 83 45 F8 01 83 7D F8 5A 7E E6 C7 45 F8 61 00 00 00 EB 14 8B }
    condition:
        all of them
}

rule Linux_Trojan_Ddostf_dc47a873 {
    meta:
        author = "Elastic Security"
        id = "dc47a873-65a0-430d-a598-95be7134f207"
        fingerprint = "f103490a9dedc0197f50ca2b412cf18d2749c8d6025fd557f1686bc38f32db52"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ddostf"
        reference_sample = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 05 88 10 8B 45 08 0F B6 10 83 E2 0F 83 CA 40 88 10 8B 45 08 C6 40 }
    condition:
        all of them
}

rule Linux_Trojan_Ddostf_cb0358a0 {
    meta:
        author = "Elastic Security"
        id = "cb0358a0-5303-4860-89ac-7dae037f5f0b"
        fingerprint = "f97c96d457532f2af5fb0e1b40ad13dcfba2479c651266b4bdd1ab2a01c0360f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ddostf"
        reference_sample = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 66 C7 45 F2 00 00 8D 45 F2 8B 55 E4 0F B6 12 88 10 0F B7 45 F2 0F }
    condition:
        all of them
}

