rule Linux_Trojan_Ladvix_db41f9d2 {
    meta:
        author = "Elastic Security"
        id = "db41f9d2-aa5c-4d26-b8ba-cece44eddca8"
        fingerprint = "d0aaa680e81f44cc555bf7799d33fce66f172563788afb2ad0fb16d3e460e8c6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ladvix"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 49 89 C4 74 45 45 85 ED 7E 26 48 89 C3 41 8D 45 FF 4D 8D 7C }
    condition:
        all of them
}

rule Linux_Trojan_Ladvix_77d184fd {
    meta:
        author = "Elastic Security"
        id = "77d184fd-a15e-40e5-ac7e-0d914cc009fe"
        fingerprint = "21361ca7c26c98903626d1167747c6fd11a5ae0d6298d2ef86430ce5be0ecd1a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ladvix"
        reference_sample = "1bb44b567b3c82f7ee0e08b16f7326d1af57efe77d608a96b2df43aab5faa9f7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 40 10 48 89 45 80 8B 85 64 FF FF FF 48 89 E2 48 89 D3 48 63 D0 48 83 }
    condition:
        all of them
}

rule Linux_Trojan_Ladvix_c9888edb {
    meta:
        author = "Elastic Security"
        id = "c9888edb-0f82-4c7a-b501-4e4d3c9c64e3"
        fingerprint = "e0e0d75a6de7a11b2391f4a8610a6d7c385df64d43fa1741d7fe14b279e1a29a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ladvix"
        reference_sample = "1d798e9f15645de89d73e2c9d142189d2eaf81f94ecf247876b0b865be081dca"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 01 83 45 E4 01 8B 45 E4 83 F8 57 76 B5 83 45 EC 01 8B 45 EC 48 }
    condition:
        all of them
}

rule Linux_Trojan_Ladvix_81fccd74 {
    meta:
        author = "Elastic Security"
        id = "81fccd74-465d-4f2e-b879-987bc47828dd"
        fingerprint = "0e983107f38a6b2a739a44ab4d37c35c5a7d8217713b280a1786511089084a95"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ladvix"
        reference = "2a183f613fca5ec30dfd82c9abf72ab88a2c57d2dd6f6483375913f81aa1c5af"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 EA 00 00 48 8D 45 EA 48 8B 55 F0 0F B6 12 88 10 0F B7 45 EA 0F }
    condition:
        all of them
}

