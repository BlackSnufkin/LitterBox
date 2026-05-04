rule MacOS_Virus_Vsearch_0dd3ec6f {
    meta:
        author = "Elastic Security"
        id = "0dd3ec6f-815f-40e1-bd53-495e0eae8196"
        fingerprint = "8adbd06894e81dc09e46d8257d4e5fcd99e714f54ffb36d5a8d6268ea25d0bd6"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Virus.Vsearch"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 2F 00 56 53 44 6F 77 6E 6C 6F 61 64 65 72 2E 6D 00 2F 4D 61 63 69 6E 74 6F 73 }
    condition:
        all of them
}

rule MacOS_Virus_Vsearch_2a0419f8 {
    meta:
        author = "Elastic Security"
        id = "2a0419f8-95b2-4f87-a37a-ee0b65e344e9"
        fingerprint = "2da9f0fc05bc8e23feb33b27142f46fb437af77766e39889a02ea843d52d17eb"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Virus.Vsearch"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 6F 72 6D 61 6C 2F 69 33 38 36 2F 56 53 44 6F 77 6E 6C 6F 61 64 65 72 2E 6F 00 }
    condition:
        all of them
}

