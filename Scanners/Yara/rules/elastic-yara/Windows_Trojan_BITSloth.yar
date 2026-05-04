rule Windows_Trojan_BITSloth_05fc3a0a {
    meta:
        author = "Elastic Security"
        id = "05fc3a0a-ce19-4042-90f8-32a43f40616e"
        fingerprint = "520722d4502230eed76b0c53fffb90bd2b818256363bc1393f51c378ff6cdd9b"
        creation_date = "2024-07-16"
        last_modified = "2024-07-26"
        threat_name = "Windows.Trojan.BITSloth"
        reference_sample = "0944b17a4330e1c97600f62717d6bae7e4a4260604043f2390a14c8d76ef1507"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_1 = "/%s/index.htm?RspID=%d" wide fullword
        $str_2 = "/%s/%08x.rpl" wide fullword
        $str_3 = "/%s/wu.htm" wide fullword
        $str_4 = "GET_DESKDOP" wide fullword
        $str_5 = "http://updater.microsoft.com/index.aspx" wide fullword
        $str_6 = "[U] update error..." wide fullword
        $str_7 = "RMC_KERNEL ..." wide fullword
        $seq_global_protocol_check = { 81 3D ?? ?? ?? ?? F9 03 00 00 B9 AC 0F 00 00 0F 46 C1 }
        $seq_exit_windows = { 59 85 C0 0F 84 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A 02 EB ?? 56 EB }
    condition:
        2 of them
}

