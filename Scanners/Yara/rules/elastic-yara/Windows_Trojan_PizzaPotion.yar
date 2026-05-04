rule Windows_Trojan_PizzaPotion_d334c613 {
    meta:
        author = "Elastic Security"
        id = "d334c613-2ef2-4627-b482-cc87589d253a"
        fingerprint = "4c1ed20b669750f2bc837b184226608e2e8473ac60881fbdd47709e147616889"
        creation_date = "2023-09-13"
        last_modified = "2023-09-20"
        threat_name = "Windows.Trojan.PizzaPotion"
        reference_sample = "37bee101cf34a84cba49adb67a555c6ebd3b8ac7c25d50247b0a014c82630003"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%s%sd.sys" ascii fullword
        $a2 = "curl -v -k -F \"file=@" ascii fullword
        $a3 = "; type=image/jpeg\" --referer drive.google.com --cookie"
        $a4 = "%sd.sys -r -inul"
        $a5 = ".xls d:\\*.xlsx d:\\*.ppt d:\\*.pptx d:\\*.pfx" ascii fullword
        $a6 = "-x\"*.exe\" -x\"*.dll\" -x\"*.jpg\" -x\"*.jpeg\""
    condition:
        4 of them
}

