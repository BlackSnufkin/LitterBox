rule Linux_Trojan_Hiddad_e35bff7b {
    meta:
        author = "Elastic Security"
        id = "e35bff7b-1a93-4cfd-a4b6-1e994c0afa98"
        fingerprint = "0ed46ca8a8bd567acf59d8a15a9597d7087975e608f42af57d36c31e777bb816"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Hiddad"
        reference_sample = "22a418e660b5a7a2e0cc1c1f3fe1d150831d75c4fedeed9817a221194522efcf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 3C 14 48 63 CF 89 FE 48 69 C9 81 80 80 80 C1 FE 1F 48 C1 E9 20 }
    condition:
        all of them
}

