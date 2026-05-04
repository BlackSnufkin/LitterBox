rule Linux_Ransomware_Gonnacry_53c3832d {
    meta:
        author = "Elastic Security"
        id = "53c3832d-ceff-407d-920b-7b6442688fa9"
        fingerprint = "7d93c26c9e069af5cef964f5747104ba6d1d0d030a1f6b1c377355223c5359a1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Ransomware.Gonnacry"
        reference_sample = "f5de75a6db591fe6bb6b656aa1dcfc8f7fe0686869c34192bfa4ec092554a4ac"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 48 89 E5 48 83 EC 10 48 89 7D F8 EB 56 48 8B 45 F8 48 8B }
    condition:
        all of them
}

