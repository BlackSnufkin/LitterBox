rule Windows_Trojan_SnakeKeylogger_af3faa65 {
    meta:
        author = "Elastic Security"
        id = "af3faa65-b19d-4267-ac02-1a3b50cdc700"
        fingerprint = "15f4ef2a03c6f5c6284ea6a9013007e4ea7dc90a1ba9c81a53a1c7407d85890d"
        creation_date = "2021-04-06"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.SnakeKeylogger"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "get_encryptedPassword" ascii fullword
        $a2 = "get_encryptedUsername" ascii fullword
        $a3 = "get_timePasswordChanged" ascii fullword
        $a4 = "get_passwordField" ascii fullword
        $a5 = "set_encryptedPassword" ascii fullword
        $a6 = "get_passwords" ascii fullword
        $a7 = "get_logins" ascii fullword
        $a8 = "GetOutlookPasswords" ascii fullword
        $a9 = "StartKeylogger" ascii fullword
        $a10 = "KeyLoggerEventArgs" ascii fullword
        $a11 = "KeyLoggerEventArgsEventHandler" ascii fullword
        $a12 = "GetDataPassword" ascii fullword
        $a13 = "_encryptedPassword" ascii fullword
        $b1 = "----------------S--------N--------A--------K--------E----------------"
        $c1 = "SNAKE-KEYLOGGER" ascii fullword
    condition:
        8 of ($a*) or #b1 > 5 or #c1 > 5
}

