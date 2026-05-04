rule Linux_Ransomware_Conti_a89c26cf {
    meta:
        author = "Elastic Security"
        id = "a89c26cf-ccec-40ca-85d3-d014b767fd6a"
        fingerprint = "c29bb1bbbd76712bbc3ddd1dfeeec40b230677339dea7441b1f34159ccbbdf9f"
        creation_date = "2023-07-30"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Conti"
        reference_sample = "95776f31cbcac08eb3f3e9235d07513a6d7a6bf9f1b7f3d400b2cf0afdb088a7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "paremeter --size cannot be %d" fullword
        $a2 = "--vmkiller" fullword
        $a3 = ".conti" fullword
        $a4 = "Cannot create file vm-list.txt" fullword
    condition:
        3 of them
}

