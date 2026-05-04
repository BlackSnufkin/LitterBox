rule Windows_Trojan_JesterStealer_b35c6f4b {
    meta:
        author = "Elastic Security"
        id = "b35c6f4b-995f-4336-94bf-fc6dc8c124f4"
        fingerprint = "d91c26a06ba7c9330e38a4744299223d3b28a96f131bce5198c4ef7c74b7d2ff"
        creation_date = "2022-02-28"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.JesterStealer"
        reference_sample = "10c3846867f70dd26c5a54332ed22070c9e5e0e4f52f05fdae12ead801f7933b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "[Decrypt Chrome Password] {0}" wide fullword
        $a2 = "Passwords.txt" wide fullword
        $a3 = "9Stealer.Recovery.FTP.FileZilla+<EnumerateCredentials>d__0" ascii fullword
        $a4 = "/C chcp 65001 && ping 127.0.0.1 && DEL /F /S /Q /A \"" wide fullword
        $a5 = "citigroup.com" wide fullword
        $a6 = "Password: {1}" wide fullword
        $a7 = "set_steamLogin" ascii fullword
    condition:
        5 of them
}

rule Windows_Trojan_JesterStealer_8f657f58 {
    meta:
        author = "Elastic Security"
        id = "8f657f58-57e0-4e5f-9223-00bfade16605"
        fingerprint = "aabf8633e853f623b75e8a354378d110442e724425f623b8c553d3522ca5dad6"
        creation_date = "2022-02-28"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.JesterStealer"
        reference_sample = "10c3846867f70dd26c5a54332ed22070c9e5e0e4f52f05fdae12ead801f7933b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 27 01 00 00 00 96 08 0B 80 79 01 6C 02 A4 27 01 00 00 00 96 08 }
    condition:
        all of them
}

