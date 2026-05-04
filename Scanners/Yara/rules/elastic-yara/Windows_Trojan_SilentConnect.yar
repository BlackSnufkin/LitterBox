rule Windows_Trojan_SilentConnect_cdc03e84 {
    meta:
        author = "Elastic Security"
        id = "cdc03e84-1d8e-4d4f-a2b1-5c55cb473cab"
        fingerprint = "dbcd8043a8359acc62f54b5ea202fac81e857e8216c336f5cc345d2b9a42996d"
        creation_date = "2026-03-04"
        last_modified = "2026-03-17"
        threat_name = "Windows.Trojan.SilentConnect"
        reference_sample = "8bab731ac2f7d015b81c2002f518fff06ea751a34a711907e80e98cf70b557db"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $peb_evade = "winhlp32.exe" wide fullword
        $rev_elevation = "wen!rotartsinimdA:noitavelE" wide fullword
        $masquerade_peb_str = "MasqueradePEB" ascii fullword
        $guid = "3E5FC7F9-9A51-4367-9063-A120244FBEC7" wide fullword
        $unique_str = "PebFucker" ascii fullword
        $peb_shellcode = { 53 48 31 DB 48 31 C0 65 48 8B 1C 25 60 00 00 00 }
        $rev_screenconnect = "tcennoCneercS" ascii wide
    condition:
        5 of them
}

