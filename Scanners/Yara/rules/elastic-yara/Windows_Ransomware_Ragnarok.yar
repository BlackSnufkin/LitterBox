rule Windows_Ransomware_Ragnarok_1cab7ea1 : beta {
    meta:
        author = "Elastic Security"
        id = "1cab7ea1-8d26-4478-ab41-659c193b5baa"
        fingerprint = "e2a8eabb08cb99c4999e05a06d0d0dce46d7e6375a72a6a5e69d718c3d54a3ad"
        creation_date = "2020-05-03"
        last_modified = "2021-08-23"
        description = "Identifies RAGNAROK ransomware"
        threat_name = "Windows.Ransomware.Ragnarok"
        reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $c1 = ".ragnarok" ascii wide fullword
    condition:
        1 of ($c*)
}

rule Windows_Ransomware_Ragnarok_7e802f95 : beta {
    meta:
        author = "Elastic Security"
        id = "7e802f95-964e-4dd9-a5d1-13a6cd73d750"
        fingerprint = "c62b3706a2024751f1346d0153381ac28057995cf95228e43affc3d1e4ad0fad"
        creation_date = "2020-05-03"
        last_modified = "2021-08-23"
        description = "Identifies RAGNAROK ransomware"
        threat_name = "Windows.Ransomware.Ragnarok"
        reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $d1 = { 68 04 94 42 00 FF 35 A0 77 43 00 }
        $d2 = { 68 90 94 42 00 FF 35 A0 77 43 00 E8 8F D6 00 00 8B 40 10 50 }
    condition:
        1 of ($d*)
}

rule Windows_Ransomware_Ragnarok_efafbe48 : beta {
    meta:
        author = "Elastic Security"
        id = "efafbe48-7740-4c21-b585-467f7ad76f8d"
        fingerprint = "a1535bc01756ac9e986eb564d712b739df980ddd61cfde5a7b001849a6b07b57"
        creation_date = "2020-05-03"
        last_modified = "2021-08-23"
        description = "Identifies RAGNAROK ransomware"
        threat_name = "Windows.Ransomware.Ragnarok"
        reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "cmd_firewall" ascii fullword
        $a2 = "cmd_recovery" ascii fullword
        $a3 = "cmd_boot" ascii fullword
        $a4 = "cmd_shadow" ascii fullword
        $a5 = "readme_content" ascii fullword
        $a6 = "readme_name" ascii fullword
        $a8 = "rg_path" ascii fullword
        $a9 = "cometosee" ascii fullword
        $a10 = "&prv_ip=" ascii fullword
    condition:
        6 of ($a*)
}

rule Windows_Ransomware_Ragnarok_5625d3f6 : beta {
    meta:
        author = "Elastic Security"
        id = "5625d3f6-7071-4a09-8ddf-faa2d081b539"
        fingerprint = "5c0a4e2683991929ff6307855bf895e3f13a61bbcc6b3c4b47d895f818d25343"
        creation_date = "2020-05-03"
        last_modified = "2021-08-23"
        description = "Identifies RAGNAROK ransomware"
        threat_name = "Windows.Ransomware.Ragnarok"
        reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $b1 = "prv_ip" ascii fullword
        $b2 = "%i.%i.%i" ascii fullword
        $b3 = "pub_ip" ascii fullword
        $b4 = "cometosee" ascii fullword
    condition:
        all of ($b*)
}

