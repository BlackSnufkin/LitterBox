rule Linux_Trojan_Sckit_a244328f {
    meta:
        author = "Elastic Security"
        id = "a244328f-1e12-4ae6-b583-ecf14a4b9d82"
        fingerprint = "eca152c730ecabbc9fe49173273199cb37b343d038084965ad880ddba3173f50"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sckit"
        reference_sample = "685da66303a007322d235b7808190c3ea78a828679277e8e03e6d8d511df0a30"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 34 D0 04 08 BB 24 C3 04 08 CD 80 C7 05 A0 EE 04 }
    condition:
        all of them
}

