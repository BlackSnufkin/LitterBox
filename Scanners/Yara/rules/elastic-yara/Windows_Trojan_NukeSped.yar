rule Windows_Trojan_NukeSped_b8e6cc07 {
    meta:
        author = "Elastic Security"
        id = "b8e6cc07-8490-49ce-b58b-db6b1fe109e2"
        fingerprint = "540f9462a7e954582df058ac3bd788e390611106c42f21508e76c8c72d1d6783"
        creation_date = "2024-12-31"
        last_modified = "2025-02-11"
        threat_name = "Windows.Trojan.NukeSped"
        reference_sample = "2dff6d721af21db7d37fc1bd8b673ec07b7114737f4df2fa8b2ecfffbe608a00"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_0 = "8877 Success!" ascii fullword
        $str_1 = "8888 Success!" ascii fullword
        $str_2 = "1234 Success!" ascii fullword
        $str_3 = "1111%d Success!" ascii fullword
        $str_4 = "4444OK" ascii fullword
        $str_5 = { 40 65 63 68 6F 20 6F 66 66 0D 0A 3A 4C 31 0D 0A 64 65 6C 20 22 25 73 22 25 73 20 22 25 73 22 20 67 6F 74 6F 20 4C 31 0D 0A 64 65 6C 20 22 25 73 22 0D 0A 00 }
    condition:
        4 of them
}

