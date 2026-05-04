rule Windows_Trojan_WhisperGate_9192618b {
    meta:
        author = "Elastic Security"
        id = "9192618b-4f3e-4503-a97f-3c4420fb79e0"
        fingerprint = "21f2a5b730a86567e68491a0d997fc52ba37f28b2164747240a74c225be3c661"
        creation_date = "2022-01-17"
        last_modified = "2022-01-17"
        threat_name = "Windows.Trojan.WhisperGate"
        reference = "https://www.elastic.co/security-labs/operation-bleeding-bear"
        reference_sample = "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "https://cdn.discordapp.com/attachments/" wide
        $a2 = "DxownxloxadDxatxxax" wide fullword
        $a3 = "powershell" wide fullword
        $a4 = "-enc UwB0AGEAcgB0AC" wide fullword
        $a5 = "Ylfwdwgmpilzyaph" wide fullword
    condition:
        all of them
}

