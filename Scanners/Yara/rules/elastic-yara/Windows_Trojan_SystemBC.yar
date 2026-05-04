rule Windows_Trojan_SystemBC_5e883723 {
    meta:
        author = "Elastic Security"
        id = "5e883723-7eaa-4992-91de-abb0ffbba54e"
        fingerprint = "add95c1f4bb279c8b189c3d64a0c2602c73363ebfad56a4077119af148dd2d87"
        creation_date = "2022-03-22"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.SystemBC"
        reference_sample = "b432805eb6b2b58dd957481aa8a973be58915c26c04630ce395753c6a5196b14"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "GET /tor/rendezvous2/%s HTTP/1.0" ascii fullword
        $a2 = "https://api.ipify.org/" ascii fullword
        $a3 = "KEY-----" ascii fullword
        $a4 = "Host: %s" ascii fullword
        $a5 = "BEGINDATA" ascii fullword
        $a6 = "-WindowStyle Hidden -ep bypass -file \"" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_SystemBC_c1b58c2f {
    meta:
        author = "Elastic Security"
        id = "c1b58c2f-8bbf-4c03-9f53-13ab2fb081cc"
        fingerprint = "dfbf98554e7fb8660e4eebd6ad2fadc394fc2a4168050390370ec358f6af1c1d"
        creation_date = "2024-05-02"
        last_modified = "2024-05-08"
        threat_name = "Windows.Trojan.SystemBC"
        reference_sample = "016fc1db90d9d18fe25ed380606346ef12b886e1db0d80fe58c22da23f6d677d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "GET %s HTTP/1.0" ascii fullword
        $a2 = "HOST1:"
        $a3 = "PORT1:"
        $a4 = "-WindowStyle Hidden -ep bypass -file \"" ascii fullword
        $a5 = "BEGINDATA" ascii fullword
        $a6 = "socks32.dll" ascii fullword
    condition:
        5 of them
}

rule Windows_Trojan_SystemBC_22bdbb5e {
    meta:
        author = "Elastic Security"
        id = "22bdbb5e-dbff-4186-b23a-b610a62b231a"
        fingerprint = "d090d2896057db2000515a29d077ad71d5d5885fc5249b9edb6f6e4e9b954c82"
        creation_date = "2025-09-18"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.SystemBC"
        reference_sample = "68d5fe65aadc29dd0761190fa36857b9546b6aeeb7ec473e2a84f07072c70311"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 8A 07 32 04 31 AA 48 FF 4D 28 48 FF C1 48 3B 4D 18 75 ?? 48 33 C9 }
        $a2 = { 48 C7 C2 28 00 00 00 4C 8D 05 ?? ?? ?? ?? 49 C7 C1 74 00 00 00 48 C7 44 24 ?? 01 00 00 00 E8 }
        $a3 = { 48 83 C4 20 66 C7 47 32 03 00 C6 47 35 01 }
        $a4 = { 75 ?? 80 3F FF 75 ?? 80 7F 01 FE 75 }
        $a5 = { 8A 8C 28 40 FE FF FF 88 8C 2B 40 FE FF FF 88 94 28 40 FE FF FF 02 CA 8A 8C 29 40 FE FF FF 30 0E 48 FF C6 48 FF CF }
        $a6 = { 48 C7 C2 32 00 00 00 4C 8D 45 ?? 49 C7 C1 0A 00 00 00 }
    condition:
        2 of them
}

