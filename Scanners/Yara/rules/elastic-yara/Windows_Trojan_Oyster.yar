rule Windows_Trojan_Oyster_6aa9dba8 {
    meta:
        author = "Elastic Security"
        id = "6aa9dba8-6b77-4dfe-b40f-b7f2449cc391"
        fingerprint = "e4d4734428a5cded4f702cb483b9c4e2e53bc43a78031a4a630e720d613d4e8a"
        creation_date = "2025-09-16"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Oyster"
        reference_sample = "462575ae35c922ca492da4f8a821d0c90aaa88a22b9578a186d3cf122894c71b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "\", \"b4\":\"" wide fullword
        $b = "C:\\Windows\\System32\\rundll32.exe \"" wide fullword
        $c = "api/kcehc" wide fullword
        $d = "api/jgfnsfnuefcnegfnehjbfncejfh" wide fullword
        $e = { C6 45 ?? 0A 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D0 C6 45 ?? 0B 8D 86 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B D0 C6 45 ?? 0C 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D0 8D 46 ?? C6 45 ?? 0D }
        $f = "Unknown ext file start" wide fullword
    condition:
        4 of them
}

