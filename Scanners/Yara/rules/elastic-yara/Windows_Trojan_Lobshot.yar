rule Windows_Trojan_Lobshot_013c1b0b {
    meta:
        author = "Elastic Security"
        id = "013c1b0b-da18-4c09-ab18-5c8428a1f4dc"
        fingerprint = "e39109421b3e156f814d33f1df327005f808f58f59bfe34ed6190076d7aace4b"
        creation_date = "2023-04-18"
        last_modified = "2023-04-23"
        threat_name = "Windows.Trojan.Lobshot"
        reference = "https://www.elastic.co/security-labs/elastic-security-labs-discovers-lobshot-malware"
        reference_sample = "e4ea88887753a936eaf3361dcc00380b88b0c210dcbde24f8f7ce27991856bf6"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str0 = "HVNC Remote Control" ascii fullword
        $str1 = " Error # %d - %08lx" ascii fullword
        $str2 = "Set  clipboard text failed." ascii fullword
        $str3 = "OK %08lx %08lx %d" ascii fullword
        $str4 = "\") & (rundll32.exe \"" wide fullword
        $str5 = "%LOCALAPPDATA%\\svc.db" wide fullword
        $str6 = "cmd.exe /c (ping -n 10 127.0.0.1) & (del /F /Q \"" wide fullword
        $seq_str_decrypt = { 8A 5A ?? 8D 52 ?? 80 EB ?? 85 FF 74 ?? C0 E0 ?? 2C ?? 0A C3 32 C1 32 C7 88 06 32 E8 83 C6 ?? 83 C5 ?? EB ?? }
        $seq_emu_check = { 8B 35 ?? ?? ?? ?? 8D 44 24 ?? 50 8D 44 24 ?? C7 44 24 ?? 48 41 4C 39 50 C7 44 24 ?? 54 48 00 00 FF D6 }
        $seq_enum_xor = { FF 15 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 83 7C 24 ?? 00 0F 84 ?? ?? ?? ?? 8B 4C 24 ?? 68 07 80 00 00 8B 41 ?? 8A 00 32 01 A2 ?? ?? ?? ?? }
        $seq_create_guid = { 8D 48 ?? 80 F9 ?? 77 ?? 2C ?? C1 E2 ?? 46 0F B6 C8 0B D1 83 FE ?? 7C ?? 5F 8B C2 5E C3 }
    condition:
        2 of ($seq*) or 5 of ($str*)
}

