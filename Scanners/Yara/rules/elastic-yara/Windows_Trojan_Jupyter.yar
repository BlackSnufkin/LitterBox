rule Windows_Trojan_Jupyter_56152e31 {
    meta:
        author = "Elastic Security"
        id = "56152e31-77c6-49fa-bbc5-c3630f11e633"
        fingerprint = "9cccc2e3d4cfe9ff090d02b143fa837f4da0c229426435b4e097f902e8c5fb01"
        creation_date = "2021-07-22"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Jupyter"
        reference_sample = "ce486097ad2491aba8b1c120f6d0aa23eaf59cf698b57d2113faab696d03c601"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%appdata%\\solarmarker.dat" ascii fullword
        $a2 = "\\AppData\\Roaming\\solarmarker.dat" wide fullword
        $b1 = "steal_passwords" ascii fullword
        $b2 = "jupyter" ascii fullword
    condition:
        1 of ($a*) or 2 of ($b*)
}

