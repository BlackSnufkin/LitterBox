rule Windows_Trojan_Bughatch_21269be4 {
    meta:
        author = "Elastic Security"
        id = "21269be4-cff1-42b9-be6b-f6a6bde40bff"
        fingerprint = "1ff55288554133690d96161c05a047ffba47778ff27d32ff656b3a194d6c26e0"
        creation_date = "2022-05-09"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.Bughatch"
        reference = "https://www.elastic.co/security-labs/bughatch-malware-analysis"
        reference_sample = "b495456a2239f3ba48e43ef295d6c00066473d6a7991051e1705a48746e8051f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 8B 45 ?? 33 D2 B9 A7 00 00 00 F7 F1 85 D2 75 ?? B8 01 00 00 00 EB 33 C0 }
        $a2 = { 8B 45 ?? 0F B7 48 04 81 F9 64 86 00 00 75 3B 8B 55 ?? 0F B7 42 16 25 00 20 00 00 ?? ?? B8 06 00 00 00 EB ?? }
        $b1 = { 69 4D 10 FD 43 03 00 81 C1 C3 9E 26 00 89 4D 10 8B 55 FC 8B 45 F8 0F B7 0C 50 8B 55 10 C1 EA 10 81 E2 FF FF 00 00 33 CA 8B 45 FC 8B 55 F8 66 89 0C 42 }
    condition:
        any of them
}

rule Windows_Trojan_Bughatch_98f3c0be {
    meta:
        author = "Elastic Security"
        id = "98f3c0be-1327-4ba2-9320-c1a9ce90b4a4"
        fingerprint = "1ac6b1285e1925349e4e578de0b2f1cf8a008cddbb1a20eb8768b1fcc4b0c8d3"
        creation_date = "2022-05-09"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.Bughatch"
        reference = "https://www.elastic.co/security-labs/bughatch-malware-analysis"
        reference_sample = "b495456a2239f3ba48e43ef295d6c00066473d6a7991051e1705a48746e8051f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "-windowstyle hidden -executionpolicy bypass -file"
        $a2 = "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"
        $a3 = "ReflectiveLoader"
        $a4 = "\\Sysnative\\"
        $a5 = "TEMP%u.CMD"
        $a6 = "TEMP%u.PS1"
        $a7 = "\\TEMP%d.%s"
        $a8 = "NtSetContextThread"
        $a9 = "NtResumeThread"
    condition:
        6 of them
}

