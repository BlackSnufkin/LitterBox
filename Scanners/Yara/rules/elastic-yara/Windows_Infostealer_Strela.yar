rule Windows_Infostealer_Strela_0dc3e4a1 {
    meta:
        author = "Elastic Security"
        id = "0dc3e4a1-13ac-4461-aac9-896f9e30d84b"
        fingerprint = "76ba0b9c5e892afc335d101dfc30355b6d704f2d723a81ddbae1cf2026ea85a4"
        creation_date = "2024-03-25"
        last_modified = "2024-09-30"
        threat_name = "Windows.Infostealer.Strela"
        reference_sample = "e6991b12e86629b38e178fef129dfda1d454391ffbb236703f8c026d6d55b9a1"
        severity = 100
        arch_context = "x86"
        scan_context = "memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "strela" fullword
        $s2 = "/server.php" fullword
        $s3 = "/out.php" fullword
        $s4 = "%s%s\\key4.db" fullword
        $s5 = "%s%s\\logins.json" fullword
        $s6 = "%s,%s,%s\n" fullword
        $old_pdb = "Projects\\StrelaDLLCompile\\Release\\StrelaDLLCompile.pdb" fullword
    condition:
        3 of ($s*) or $old_pdb
}

