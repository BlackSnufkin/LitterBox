rule Windows_Trojan_Supper_664c9ab3 {
    meta:
        author = "Elastic Security"
        id = "664c9ab3-7413-4390-a122-f01762f967c2"
        fingerprint = "1c59c03565b539d309e7fdd31bc154d61c966d6690e91be7b15c9cb3aa87c680"
        creation_date = "2025-09-22"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Supper"
        reference_sample = "3a7b8c4762f3490794790a2e98377af7ed1438150e2d94b1809a7571bb05067d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "schtasks.exe /Create /SC MINUTE /TN GoogleUpdateTask /TR \"cmd.exe /C del \\\"%s\\\" && schtasks.exe /Delete /TN GoogleUpdateTask /F\" /F" fullword
        $a2 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"" fullword
        $a3 = "%d.%d.%d.%d" fullword
        $a4 = "(%d)\trecv type-%d len %d (0x%x)\n" fullword
        $a5 = "fail run cmd\n" fullword
        $b1 = { F3 0F 7E 0D 38 D4 00 00 81 71 08 4D 4D 4D 4D F3 0F 7E 01 66 0F EF C1 66 0F D6 01 C3 }
    condition:
        3 of ($a*) or $b1
}

