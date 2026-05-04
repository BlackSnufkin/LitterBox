rule Windows_Ransomware_WhisperGate_c80f3b4b {
    meta:
        author = "Elastic Security"
        id = "c80f3b4b-f91b-4b8d-908e-f64c2c5d4b30"
        fingerprint = "e8ad6a7cfabf96387deee56f38b0f0ba6d8fe85e7be9f153ccf72d69ee5db1c9"
        creation_date = "2022-01-17"
        last_modified = "2022-01-17"
        threat_name = "Windows.Ransomware.WhisperGate"
        reference_sample = "a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $buffer = { E8 ?? ?? ?? ?? BE 20 40 40 00 29 C4 8D BD E8 DF FF FF E8 ?? ?? ?? ?? B9 00 08 00 00 F3 A5 }
        $note = { 59 6F 75 72 20 68 61 72 64 20 64 72 69 76 65 20 68 61 73 20 62 65 65 6E 20 63 6F 72 72 75 70 74 65 64 2E 0D 0A }
    condition:
        all of them
}

rule Windows_Ransomware_WhisperGate_3476008e {
    meta:
        author = "Elastic Security"
        id = "3476008e-1c98-4606-b60b-7fef0e360711"
        fingerprint = "0b8caff8cf9342bd50053712bf4c9aeab68532e340cc5e6cf400105afc150e39"
        creation_date = "2022-01-18"
        last_modified = "2022-01-18"
        threat_name = "Windows.Ransomware.WhisperGate"
        reference_sample = "9ef7dbd3da51332a78eff19146d21c82957821e464e8133e9594a07d716d892d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "cmd.exe /min /C ping 111.111.111.111 -n 5 -w 10 > Nul & Del /f /q \"%s\"" ascii fullword
        $a2 = "%.*s.%x" wide fullword
        $a3 = "A:\\Windows" wide fullword
        $a4 = ".ONETOC2" wide fullword
    condition:
        all of them
}

