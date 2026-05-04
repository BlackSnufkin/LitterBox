rule Windows_Ransomware_DragonForce_44bb8f0d {
    meta:
        author = "Elastic Security"
        id = "44bb8f0d-9648-426d-bd1c-0e16ccc8ad04"
        fingerprint = "990654f2598e9f9878ba61e0eeef67522cc6e851c49fc9ca4874131a26c120bb"
        creation_date = "2025-05-28"
        last_modified = "2026-02-02"
        threat_name = "Windows.Ransomware.DragonForce"
        reference_sample = "d06b5a200292fedcfb4d4aecac32387a2e5b5bb09aaab5199c56bab3031257d6"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_1 = "%04d-%02d-%02dT%02d:%02d:00Z" wide fullword
        $str_2 = ".dragonforce_encrypted" wide fullword
        $seq_1 = { C6 44 24 19 45 C6 44 24 1A 55 C6 44 24 1B 3C C6 44 24 1C 55 C6 44 24 1D 3A C6 44 24 1E 55 C6 44 24 1F 3F }
        $seq_2 = { C6 45 D4 00 C6 45 D5 4F C6 45 D6 69 C6 45 D7 28 C6 45 D8 69 C6 45 D9 1A C6 45 DA 69 C6 45 DB 3B C6 45 DC }
        $seq_3 = { C6 45 8C 00 C6 45 8D 55 C6 45 8E 02 C6 45 8F 4C C6 45 90 02 C6 45 91 73 C6 45 92 02 }
    condition:
        3 of them
}

