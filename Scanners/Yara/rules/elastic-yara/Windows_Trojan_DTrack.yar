rule Windows_Trojan_DTrack_57db861f {
    meta:
        author = "Elastic Security"
        id = "57db861f-669b-43a7-9284-24615b606f70"
        fingerprint = "a189e255f533d4ff4562c3a59c5dfe8462ad25fcd179a48d54fa1179abf0c9b2"
        creation_date = "2024-12-27"
        last_modified = "2025-02-11"
        threat_name = "Windows.Trojan.DTrack"
        reference_sample = "c8df8511bccc588daf87583ea40836acfddefb5416b860799835ea6f93f9ce5f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_0 = "%sExecute_%s.log" fullword
        $str_1 = "%02X:%02X:%02X:%02X:%02X:%02X" fullword
        $str_2 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d : " fullword
        $log_0 = "[+] DownloadToFile" fullword
        $log_1 = "[+] DownloadCommand" fullword
        $log_2 = "[+] StartupThread" fullword
        $log_3 = "[+] Connect" fullword
        $log_4 = "[+] CPT.." fullword
        $binary_0 = { 8B 45 ?? C1 E8 08 8B 4D ?? C1 E9 02 33 4D ?? 8B 55 ?? C1 EA 03 33 CA 8B 55 ?? C1 EA 07 33 CA }
    condition:
        (all of ($str_*)) or (all of ($log_*)) or (1 of ($str_*) and $binary_0)
}

