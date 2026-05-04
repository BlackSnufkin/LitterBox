rule Windows_Trojan_Gh0st_ee6de6bc {
    meta:
        author = "Elastic Security"
        id = "ee6de6bc-1648-4a77-9607-e2a211c7bda4"
        fingerprint = "3c529043f34ad8a8692b051ad7c03206ce1aafc3a0eb8fcf7f5bcfdcb8c1b455"
        creation_date = "2021-06-10"
        last_modified = "2021-08-23"
        description = "Identifies a variant of Gh0st Rat"
        threat_name = "Windows.Trojan.Gh0st"
        reference_sample = "ea1dc816dfc87c2340a8b8a77a4f97618bccf19ad3b006dce4994be02e13245d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = ":]%d-%d-%d  %d:%d:%d" ascii fullword
        $a2 = "[Pause Break]" ascii fullword
        $a3 = "f-secure.exe" ascii fullword
        $a4 = "Accept-Language: zh-cn" ascii fullword
    condition:
        all of them
}

