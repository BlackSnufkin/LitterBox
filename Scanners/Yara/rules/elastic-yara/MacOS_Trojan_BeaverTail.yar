rule MacOS_Trojan_BeaverTail_90b8abd6 {
    meta:
        author = "Elastic Security"
        id = "90b8abd6-3111-433b-b2f7-217715a76610"
        fingerprint = "97f79082f8ac7326d6169bf892b28b81b040bf172bf89e7ff3b7b0bbd8c1b9a6"
        creation_date = "2026-02-25"
        last_modified = "2026-04-06"
        threat_name = "MacOS.Trojan.BeaverTail"
        reference_sample = "0f5f0a3ac843df675168f82021c24180ea22f764f87f82f9f77fe8f0ba0b7132"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = "Upload LDB Finshed!!!" fullword
        $b = "Download Python Success!" fullword
        $c = "Download Client Success!" fullword
        $d = "/.pyp/python.exe" fullword
        $e = "/Library/Keychains/login.keychain-db" fullword
        $f = "clientDownFinished" fullword
        $g = "upLDBFinished" fullword
    condition:
        4 of them
}

