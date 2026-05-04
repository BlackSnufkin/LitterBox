rule Windows_Trojan_FinalDraft_ce03cf22 {
    meta:
        author = "Elastic Security"
        id = "ce03cf22-8016-44e0-8d09-fbe1b575f045"
        fingerprint = "856711354d1dd393faca657600631b78b6e53f8b7c24d3f2e5c7937b3f41d92d"
        creation_date = "2025-01-23"
        last_modified = "2025-02-04"
        threat_name = "Windows.Trojan.FinalDraft"
        reference_sample = "39e85de1b1121dc38a33eca97c41dbd9210124162c6d669d28480c833e059530"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_derive_encryption_key = { 4D 6B C0 1F 48 0F BE 02 4C 03 C0 48 03 D7 49 3B D2 }
        $seq_decrypt_configuration = { 48 8B ?? 83 E0 ?? [4-9] 30 04 0A 48 [2] 48 81 ?? 9A 14 00 00 72 }
        $seq_magic = { 12 34 AB CD FF FF CD AB 34 12 }
        $str_injection_target_0 = "%c:\\Windows\\SysWOW64\\mspaint.exe" fullword
        $str_injection_target_1 = "%c:\\Windows\\System32\\mspaint.exe" fullword
        $str_injection_target_2 = "%c:\\Windows\\SysWOW64\\conhost.exe" fullword
        $str_injection_target_3 = "%c:\\Windows\\System32\\conhost.exe" fullword
        $str_active_connections_fmt_str = "%-7s%-34s%-34s%-13s%-7s" fullword
        $str_graph_parameters = "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&grant_type=refresh" fullword
        $str_err_code = "err code: 0x%08x" fullword
    condition:
        5 of them
}

