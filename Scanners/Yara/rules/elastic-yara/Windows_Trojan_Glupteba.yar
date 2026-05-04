rule Windows_Trojan_Glupteba_70557305 {
    meta:
        author = "Elastic Security"
        id = "70557305-3d11-4dde-b53b-94f1ecc0380b"
        fingerprint = "bac7daa5c491de8f8a75b203cdb1cdab2c10633aa45a82e6b04d2f577e3e8415"
        creation_date = "2021-08-08"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Glupteba"
        reference_sample = "3ad13fd7968f9574d2c822e579291c77a0c525991cfb785cbe6cdd500b737218"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%TEMP%\\app.exe && %TEMP%\\app.exe"
        $a2 = "is unavailable%d smbtest"
        $a3 = "discovered new server %s"
        $a4 = "uldn't get usernamecouldn't hide servicecouldn't"
        $a5 = "TERMINATE PROCESS: %ws, %d, %d" ascii fullword
        $a6 = "[+] Extracting vulnerable driver as \"%ws\"" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Glupteba_4669dcd6 {
    meta:
        author = "Elastic Security"
        id = "4669dcd6-8e04-416d-91c0-f45816430869"
        fingerprint = "5b598640f42a99b00d481031f5fcf143ffcc32ef002eac095a14edb18d5b02c9"
        creation_date = "2021-08-08"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Glupteba"
        reference_sample = "1b55042e06f218546db5ddc52d140be4303153d592dcfc1ce90e6077c05e77f7"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 40 C3 8B 44 24 48 8B 4C 24 44 89 81 AC 00 00 00 8B 44 24 4C 89 81 B0 00 }
    condition:
        all of them
}

