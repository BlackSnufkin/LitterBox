rule Windows_Trojan_Pandastealer_8b333e76 {
    meta:
        author = "Elastic Security"
        id = "8b333e76-f723-4093-ad72-2f5d42aaa9c9"
        fingerprint = "873af8643b7f08b159867c3556654a5719801aa82e1a1f6402029afad8c01487"
        creation_date = "2021-09-02"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Pandastealer"
        reference_sample = "ec346bd56be375b695b4bc76720959fa07d1357ffc3783eb61de9b8d91b3d935"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "] - [user: " ascii fullword
        $a2 = "[-] data unpacked failed" ascii fullword
        $a3 = "[+] data unpacked" ascii fullword
        $a4 = "\\history\\" ascii fullword
        $a5 = "PlayerName" ascii fullword
    condition:
        all of them
}

