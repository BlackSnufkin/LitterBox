rule Windows_Trojan_Darkcomet_1df27bcc {
    meta:
        author = "Elastic Security"
        id = "1df27bcc-9f18-48d4-bd7f-73bdc7cb1e63"
        fingerprint = "63b77999860534b71b7b4e7b3da9df175ccd0009f4c13215a59c6b83e0e95b3b"
        creation_date = "2021-08-16"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Darkcomet"
        reference_sample = "7fbe87545eef49da0df850719536bb30b196f7ad2d5a34ee795c01381ffda569"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "BTRESULTHTTP Flood|Http Flood task finished!|" ascii fullword
        $a2 = "is now open!|" ascii fullword
        $a3 = "ActiveOnlineKeylogger" ascii fullword
        $a4 = "#BOT#RunPrompt" ascii fullword
        $a5 = "GETMONITORS" ascii fullword
    condition:
        all of them
}

