rule Windows_Trojan_Limerat_24269a79 {
    meta:
        author = "Elastic Security"
        id = "24269a79-0172-4da5-9b4d-f61327072bf0"
        fingerprint = "cb714cd787519216d25edaad9f89a9c0ce1b8fbbbcdf90bda4c79f5d85fdf381"
        creation_date = "2021-08-17"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Limerat"
        reference_sample = "ec781a714d6bc6fac48d59890d9ae594ffd4dbc95710f2da1f1aa3d5b87b9e01"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "schtasks /create /f /sc ONLOGON /RL HIGHEST /tn LimeRAT-Admin /tr \"'" wide fullword
    condition:
        all of them
}

