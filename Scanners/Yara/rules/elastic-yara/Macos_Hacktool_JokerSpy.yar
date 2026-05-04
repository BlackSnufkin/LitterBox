rule Macos_Hacktool_JokerSpy_58a6b26d {
    meta:
        author = "Elastic Security"
        id = "58a6b26d-13dd-485a-bac3-77a1053c3a02"
        fingerprint = "71423d5c4c917917281b7e0f644142a0570df7a5a7ea568506753cb6eabef1c0"
        creation_date = "2023-06-19"
        last_modified = "2023-06-19"
        threat_name = "Macos.Hacktool.JokerSpy"
        reference = "https://www.elastic.co/security-labs/inital-research-of-jokerspy"
        reference_sample = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $str1 = "ScreenRecording: NO" fullword
        $str2 = "Accessibility: NO" fullword
        $str3 = "Accessibility: YES" fullword
        $str4 = "eck13XProtectCheck"
        $str5 = "Accessibility: NO" fullword
        $str6 = "kMDItemDisplayName = *TCC.db" fullword
    condition:
        5 of them
}

