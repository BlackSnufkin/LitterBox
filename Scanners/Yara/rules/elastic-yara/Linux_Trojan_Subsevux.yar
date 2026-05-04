rule Linux_Trojan_Subsevux_e9e80c1e {
    meta:
        author = "Elastic Security"
        id = "e9e80c1e-c064-47cf-91f2-0561dd5c9bcd"
        fingerprint = "bbd7a2d80e545d0cae7705a53600f6b729918a3d655bc86b2db83f15d4e550e3"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Subsevux"
        reference_sample = "a4ccd399ea99d4e31fbf2bbf8017c5368d29e630dc2985e90f07c10c980fa084"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C0 89 45 F4 83 7D F4 00 79 1C 83 EC 0C 68 }
    condition:
        all of them
}

