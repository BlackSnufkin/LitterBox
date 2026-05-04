rule Windows_Trojan_DCRat_1aeea1ac {
    meta:
        author = "Elastic Security"
        id = "1aeea1ac-69b9-4cc6-91af-18b7a79f35ce"
        fingerprint = "fc67d76dc916b7736de783aa245483381a8fe071c533f3761e550af80a873fe9"
        creation_date = "2022-01-15"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.DCRat"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "havecamera" ascii fullword
        $a2 = "timeout 3 > NUL" wide fullword
        $a3 = "START \"\" \"" wide fullword
        $a4 = "L2Mgc2NodGFza3MgL2NyZWF0ZSAvZiAvc2Mgb25sb2dvbiAvcmwgaGlnaGVzdCAvdG4g" wide fullword
        $a5 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA==" wide fullword
        $b1 = "DcRatByqwqdanchun" ascii fullword
        $b2 = "DcRat By qwqdanchun1" ascii fullword
    condition:
        5 of ($a*) or 1 of ($b*)
}

