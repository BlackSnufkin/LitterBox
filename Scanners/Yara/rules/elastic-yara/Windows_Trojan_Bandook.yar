rule Windows_Trojan_Bandook_38497690 {
    meta:
        author = "Elastic Security"
        id = "38497690-6663-47c9-a864-0bbe6a3f7a8b"
        fingerprint = "b6debea805a8952b9b7473ad7347645e4aced3ecde8d6e53fa2d82c35b285b3c"
        creation_date = "2022-08-10"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.Bandook"
        reference_sample = "4d079586a51168aac708a9ab7d11a5a49dfe7a16d9ced852fbbc5884020c0c97"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "%s~!%s~!%s~!%s~!%s~!%s~!"
        $str2 = "ammyy.abc"
        $str3 = "StealUSB"
        $str4 = "DisableMouseCapture"
        $str5 = "%sSkype\\%s\\config.xml"
        $str6 = "AVE_MARIA"
    condition:
        3 of them
}

