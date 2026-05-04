rule Windows_Trojan_XtremeRAT_cd5b60be {
    meta:
        author = "Elastic Security"
        id = "cd5b60be-4685-425a-8fe1-8366c0e5b84a"
        fingerprint = "2ee35d7c34374e9f5cffceb36fe1912932288ea4e8211a8b77430b98a9d41fb2"
        creation_date = "2022-03-15"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.XtremeRAT"
        reference_sample = "735f7bf255bdc5ce8e69259c8e24164e5364aeac3ee78782b7b5275c1d793da8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s01 = "SOFTWARE\\XtremeRAT" wide fullword
        $s02 = "XTREME" wide fullword
        $s03 = "STARTSERVERBUFFER" wide fullword
        $s04 = "ENDSERVERBUFFER" wide fullword
        $s05 = "ServerKeyloggerU" ascii fullword
        $s06 = "TServerKeylogger" ascii fullword
        $s07 = "XtremeKeylogger" wide fullword
        $s08 = "XTREMEBINDER" wide fullword
        $s09 = "UnitInjectServer" ascii fullword
        $s10 = "shellexecute=" wide fullword
    condition:
        7 of ($s*)
}

