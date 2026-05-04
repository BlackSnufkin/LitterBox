rule Windows_Trojan_Quasarrat_e52df647 {
    meta:
        author = "Elastic Security"
        id = "e52df647-c197-4790-b051-8951fba80c3b"
        fingerprint = "c888f0856c6568b83ab60193f8144a61e758e6ff53f6ead8565282ae8b3a9815"
        creation_date = "2021-06-27"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Quasarrat"
        reference_sample = "a58efd253a25cc764d63476931da2ddb305a0328253a810515f6735a6690de1d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "GetKeyloggerLogsResponse" ascii fullword
        $a2 = "DoDownloadAndExecute" ascii fullword
        $a3 = "http://api.ipify.org/" wide fullword
        $a4 = "Domain: {1}{0}Cookie Name: {2}{0}Value: {3}{0}Path: {4}{0}Expired: {5}{0}HttpOnly: {6}{0}Secure: {7}" wide fullword
        $a5 = "\" /sc ONLOGON /tr \"" wide fullword
    condition:
        4 of them
}

