rule Windows_Hacktool_SharpGPOAbuse_14ea480e {
    meta:
        author = "Elastic Security"
        id = "14ea480e-fbd5-4dd3-885c-9a13bfb4400b"
        fingerprint = "1f86d5dfc193076127dcc4355cbf0c4bdffc0785ca2daf8e1364d76ee273b343"
        creation_date = "2024-03-25"
        last_modified = "2024-05-08"
        threat_name = "Windows.Hacktool.SharpGPOAbuse"
        reference_sample = "d13f87b9eaf09ef95778b2f1469aa34d03186d127c8f73c73299957d386c78d1"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $name = "SharpGPOAbuse" wide fullword
        $s1 = "AddUserTask" wide fullword
        $s2 = "AddComputerTask" wide fullword
        $s3 = "AddComputerScript" wide fullword
        $s4 = "AddUserScript" wide fullword
        $s5 = "GPOName" wide fullword
        $s6 = "ScheduledTasks" wide fullword
        $s7 = "NewImmediateTask" wide fullword
    condition:
        ($name and 1 of ($s*)) or all of ($s*)
}

