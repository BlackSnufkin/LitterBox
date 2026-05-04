rule Windows_Trojan_DoubleBack_d2246a35 {
    meta:
        author = "Elastic Security"
        id = "d2246a35-e582-4707-acd0-f04bb66df722"
        fingerprint = "949f8d30125fad133f4b897c945c6aa0eccda5456dc887bde4c0a5affece5195"
        creation_date = "2022-05-29"
        last_modified = "2022-07-18"
        threat_name = "Windows.Trojan.DoubleBack"
        reference_sample = "03d2a0747d06458ccddf65ff5847a511a105e0ad4dcb5134082623af6f705012"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "client.dll" ascii fullword
        $s2 = "=i.ext;" ascii fullword
        $s3 = "## dbg delay" ascii fullword
        $s4 = "ehost"
        $s5 = "msie"
        $s6 = "POST"
        $s7 = "%s(%04Xh:%u/%u)[%s %s]: %s" ascii fullword
        $x64_powershell_msi_check = { 81 3C 39 70 6F 77 65 74 ?? 81 3C 39 6D 73 69 65 41 }
        $x86_powershell_msi_check = { 81 3C 30 70 6F 77 65 74 ?? 81 3C 30 6D 73 69 65 6A 03 5A 0F }
        $x64_salted_hash_func = { 8B 7D ?? 4C 8D 45 ?? 81 C7 ?? ?? ?? ?? 48 8D 4D ?? BA 04 00 00 00 89 7D ?? }
        $x86_salted_hash_func = { 8B 75 ?? 8D 45 ?? 50 6A ?? 81 C6 ?? ?? ?? ?? 8D 4D ?? 5A 89 75 ?? }
        $x64_guid = { 48 83 EC ?? 45 33 C9 41 B8 DD CC BB AA 45 8D 51 ?? }
        $x86_guid = { 55 8B EC 83 EC ?? B8 DD CC BB AA 56 57 6A ?? 8D 75 ?? 5F }
    condition:
        5 of ($s*) or 2 of ($x64_*) or 2 of ($x86_*)
}

