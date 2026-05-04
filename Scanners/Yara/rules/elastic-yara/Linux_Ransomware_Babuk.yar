rule Linux_Ransomware_Babuk_bd216cab {
    meta:
        author = "Elastic Security"
        id = "bd216cab-6532-4a71-9353-8ad692550b97"
        fingerprint = "c7517a40759de20edf7851d164c0e4ba71de049f8ea964f15ab5db12c35352ad"
        creation_date = "2024-05-09"
        last_modified = "2024-06-12"
        threat_name = "Linux.Ransomware.Babuk"
        reference_sample = "d305a30017baef4f08cee38a851b57869676e45c66e64bb7cc58d40bf0142fe0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "Whole files count: %d"
        $a2 = "Doesn't encrypted files: %d"
    condition:
        all of them
}

