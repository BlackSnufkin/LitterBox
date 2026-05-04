rule Windows_Ransomware_Crytox_29859242 {
    meta:
        author = "Elastic Security"
        id = "29859242-adf4-4d17-afdf-dbc02f5b787b"
        fingerprint = "999713c1815d61904f13f7f9cbaf34b116f53af223b2aac20bf0d88af107dbae"
        creation_date = "2024-01-18"
        last_modified = "2024-02-08"
        threat_name = "Windows.Ransomware.Crytox"
        reference_sample = "55a27cb6280f31c077987d338151b13e9dc0cc1c14d47a32e64de6d6c1a6a742"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 83 C7 20 D7 C1 C8 08 D7 C1 C8 08 D7 C1 C8 08 D7 C1 C8 10 33 C2 33 47 E0 D0 E2 }
    condition:
        all of them
}

