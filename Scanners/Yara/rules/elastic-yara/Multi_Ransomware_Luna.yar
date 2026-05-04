rule Multi_Ransomware_Luna_8614d3d7 {
    meta:
        author = "Elastic Security"
        id = "8614d3d7-7fd2-4cf9-aa97-48a8d9333f38"
        fingerprint = "90c97ecfce451e1373af0d7538cf12991cc844d05c99ee18570e176143ccd899"
        creation_date = "2022-08-02"
        last_modified = "2022-08-16"
        threat_name = "Multi.Ransomware.Luna"
        reference = "https://www.elastic.co/security-labs/luna-ransomware-attack-pattern"
        reference_sample = "1cbbf108f44c8f4babde546d26425ca5340dccf878d306b90eb0fbec2f83ab51"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str_extensions = ".ini.exe.dll.lnk"
        $str_ransomnote_bs64 = "W1dIQVQgSEFQUEVORUQ/XQ0KDQpBbGwgeW91ciBmaWxlcyB3ZXJlIG1vdmVkIHRvIHNlY3VyZSBzdG9yYWdlLg0KTm9ib"
        $str_path = "/home/username/"
        $str_error1 = "Error while writing encrypted data to:"
        $str_error2 = "Error while writing public key to:"
        $str_error3 = "Error while renaming file:"
        $chunk_calculation0 = { 48 8D ?? 00 00 48 F4 48 B9 8B 3D 10 B6 9A 5A B4 36 48 F7 E1 48 }
        $chunk_calculation1 = { 48 C1 EA 12 48 89 D0 48 C1 E0 05 48 29 D0 48 29 D0 48 3D C4 EA 00 00 }
    condition:
        5 of ($str_*) or all of ($chunk_*)
}

