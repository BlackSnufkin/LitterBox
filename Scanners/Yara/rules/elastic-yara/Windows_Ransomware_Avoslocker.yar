rule Windows_Ransomware_Avoslocker_7ae4d4f2 {
    meta:
        author = "Elastic Security"
        id = "7ae4d4f2-be5f-4aad-baaa-4182ff9cf996"
        fingerprint = "0e5ff268ed2b62f9d31df41192135145094849a4e6891407568c3ea27ebf66bb"
        creation_date = "2021-07-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Ransomware.Avoslocker"
        reference_sample = "43b7a60c0ef8b4af001f45a0c57410b7374b1d75a6811e0dfc86e4d60f503856"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "drive %s took %f seconds" ascii fullword
        $a2 = "client_rsa_priv: %s" ascii fullword
        $a3 = "drive: %s" ascii fullword
        $a4 = "Map: %s" ascii fullword
        $a5 = "encrypting %ls failed" wide fullword
    condition:
        all of them
}

