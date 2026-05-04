rule Windows_Trojan_Bumblebee_35f50bea {
    meta:
        author = "Elastic Security"
        id = "35f50bea-c497-4cc6-b915-8ad3aca7bee6"
        fingerprint = "f2e07a9b7d143ca13852f723e7d0bd55365d6f8b5d9315b7e24b7f1101010820"
        creation_date = "2022-04-28"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.Bumblebee"
        reference_sample = "9fff05a5aa9cbbf7d37bc302d8411cbd63fb3a28dc6f5163798ae899b9edcda6"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 43 28 45 33 D2 4D 8D 0C 00 44 88 54 24 20 66 48 0F 7E C9 66 0F }
        $a2 = { 31 DA 48 31 C7 45 ?? C9 B9 E8 03 C7 45 ?? 00 00 BA 01 C7 45 ?? 00 00 00 48 C7 45 ?? B8 88 77 66 C7 45 ?? 55 44 33 22 C7 45 ?? 11 FF D0 EB C6 45 }
    condition:
        any of them
}

rule Windows_Trojan_Bumblebee_70bed4f3 {
    meta:
        author = "Elastic Security"
        id = "70bed4f3-f515-4186-ac6c-e9db72b8a95a"
        fingerprint = "016477598ce022cc75f591d1c72535a3353ecc4e888642e72aa29476464a8c2f"
        creation_date = "2022-04-28"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.Bumblebee"
        reference_sample = "9fff05a5aa9cbbf7d37bc302d8411cbd63fb3a28dc6f5163798ae899b9edcda6"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Checking Virtual PC processes %s " wide fullword
        $a2 = "SELECT * FROM Win32_ComputerSystemProduct" ascii fullword
        $a3 = "Injection-Date" ascii fullword
        $a4 = " -Command \"Wait-Process -Id " ascii fullword
        $a5 = "%WINDIR%\\System32\\wscript.exe" wide fullword
        $a6 = "objShell.Run \"rundll32.exe my_application_path"
        $a7 = "Checking reg key HARDWARE\\Description\\System - %s is set to %s" wide fullword
    condition:
        5 of them
}

