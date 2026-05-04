rule Windows_Trojan_PipeDance_01c18057 {
    meta:
        author = "Elastic Security"
        id = "01c18057-258d-4242-928c-26972a2f1e76"
        fingerprint = "01b8c127974ec8e3db0fc68db8d11cd4f4247c0128a8630f64c7bd20726220af"
        creation_date = "2023-02-02"
        last_modified = "2023-02-22"
        threat_name = "Windows.Trojan.PipeDance"
        reference = "https://www.elastic.co/security-labs/twice-around-the-dance-floor-with-pipedance"
        reference_sample = "9d3f739e35182992f1e3ade48b8999fb3a5049f48c14db20e38ee63eddc5a1e7"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "%-5d %-30s %-4s %-7d %s" wide fullword
        $str2 = "PID   Name   Arch Session User" wide fullword
        $str3 = "%s %7.2f B" wide fullword
        $str4 = "\\\\.\\pipe\\%s.%d" ascii fullword
        $seq_rc4 = { 8D 46 ?? 0F B6 F0 8A 14 3E 0F B6 C2 03 C1 0F B6 C8 89 4D ?? 8A 04 0F 88 04 3E 88 14 0F 0F B6 0C 3E 0F B6 C2 03 C8 0F B6 C1 8B 4D ?? 8A 04 38 30 04 0B 43 8B 4D ?? 3B 5D ?? 72 ?? }
        $seq_srv_resp = { 8B CE 50 6A 04 5A E8 ?? ?? ?? ?? B8 00 04 00 00 8D 4E ?? 50 53 8B D0 E8 ?? ?? ?? ?? B8 08 02 00 00 8D 8E ?? ?? ?? ?? 50 57 8B D0 E8 ?? ?? ?? ?? }
        $seq_cmd_dispatch = { 83 FE 29 0F 87 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 83 FE 06 0F 87 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8B C6 33 D2 2B C2 0F 84 ?? ?? ?? ?? 83 E8 01 }
        $seq_icmp = { 59 6A 61 5E 89 45 ?? 8B D0 89 5D ?? 2B F0 8D 04 16 8D 4B ?? 88 0A 83 F8 77 7E ?? 80 E9 17 88 0A 43 42 83 FB 20 }
    condition:
        4 of ($str*) or 2 of ($seq*)
}

