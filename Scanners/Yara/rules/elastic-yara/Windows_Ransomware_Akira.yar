rule Windows_Ransomware_Akira_c8c298ba {
    meta:
        author = "Elastic Security"
        id = "c8c298ba-2760-4880-a54a-3d916049d0ab"
        fingerprint = "81c6dfa172ce7f4254e3cc74fcb71786336d39438d6e9379f7611495f54227c9"
        creation_date = "2024-05-02"
        last_modified = "2024-05-08"
        threat_name = "Windows.Ransomware.Akira"
        reference_sample = "a2df5477cf924bd41241a3326060cc2f913aff2379858b148ddec455e4da67bc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "akira_readme.txt" ascii fullword
        $a2 = "Number of threads to encrypt = " ascii fullword
        $a3 = "write_encrypt_info error:" ascii fullword
        $a4 = "Log-%d-%m-%Y-%H-%M-%S" ascii fullword
        $a5 = "--encryption_path" wide fullword
        $a6 = "--encryption_percent" wide fullword
    condition:
        3 of them
}

