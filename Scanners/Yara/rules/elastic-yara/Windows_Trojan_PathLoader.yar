rule Windows_Trojan_PathLoader_d62822f8 {
    meta:
        author = "Elastic Security"
        id = "d62822f8-202b-41f8-8c04-75cbc975fcdc"
        fingerprint = "dd257c5039fe21b73ac339275a26d9e677953c6dec11f4c2a5e82f76c8bbd2f0"
        creation_date = "2024-12-26"
        last_modified = "2025-02-04"
        threat_name = "Windows.Trojan.PathLoader"
        reference_sample = "9a11d6fcf76583f7f70ff55297fb550fed774b61f35ee2edd95cf6f959853bcf"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $debug_str = "[-] WinHttpSendRequest %d\n" ascii fullword
        $fnv_GetProcAddress = { 44 69 D2 93 01 00 01 45 84 C0 75 D4 41 81 FA 0C B5 82 01 }
        $peb_GetTickCount = { 48 3D 60 EA 00 00 0F 8F ?? ?? ?? ?? 65 48 8B 04 25 60 00 00 00 48 8B 40 18 48 8B 40 10 }
        $base64_http = { 36 31 34 38 35 32 33 30 36 33 34 }
    condition:
        3 of them
}

