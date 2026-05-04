rule Windows_Trojan_Remcos_b296e965 {
    meta:
        author = "Elastic Security"
        id = "b296e965-a99e-4446-b969-ba233a2a8af4"
        fingerprint = "a5267bc2dee28a3ef58beeb7e4a151699e3e561c16ce0ab9eb27de33c122664d"
        creation_date = "2021-06-10"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Remcos"
        reference = "https://www.elastic.co/security-labs/exploring-the-ref2731-intrusion-set"
        reference_sample = "0ebeffa44bd1c3603e30688ace84ea638fbcf485ca55ddcfd6fbe90609d4f3ed"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Remcos restarted by watchdog!" ascii fullword
        $a2 = "Mutex_RemWatchdog" ascii fullword
        $a3 = "%02i:%02i:%02i:%03i"
        $a4 = "* Remcos v" ascii fullword
    condition:
        2 of them
}

rule Windows_Trojan_Remcos_7591e9f1 {
    meta:
        author = "Elastic Security"
        id = "7591e9f1-452d-4731-9bec-545fb0272c80"
        fingerprint = "9436c314f89a09900a9b3c2fd9bab4a0423912427cf47b71edce5eba31132449"
        creation_date = "2023-06-23"
        last_modified = "2023-07-10"
        threat_name = "Windows.Trojan.Remcos"
        reference = "https://www.elastic.co/security-labs/exploring-the-ref2731-intrusion-set"
        reference_sample = "4e6e5ecd1cf9c88d536c894d74320c77967fe08c75066098082bf237283842fa"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "ServRem" ascii fullword
        $a2 = "Screenshots" ascii fullword
        $a3 = "MicRecords" ascii fullword
        $a4 = "remcos.exe" wide nocase fullword
        $a5 = "Remcos" wide fullword
        $a6 = "logs.dat" wide fullword
    condition:
        3 of them
}

rule Windows_Trojan_Remcos_921ef449 {
    meta:
        author = "Elastic Security"
        id = "921ef449-002a-488c-870c-04e6f6194bc9"
        fingerprint = "4f8bfcec82292fd1dd1d660533adc34d91f630d25ab4640dab231b9cec632d60"
        creation_date = "2025-07-29"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Remcos"
        reference_sample = "41fc369e2f92f3c5809817271a76d32beb607102aae308b172a7b0389d6eef6e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Remcos Agent initialized (" fullword
        $a2 = "Remcos v" fullword
        $a3 = "Uploading file to Controller: " fullword
        $a4 = "alarm.wav" fullword
        $a5 = "[%04i/%02i/%02i %02i:%02i:%02i " wide fullword
        $a6 = "time_%04i%02i%02i_%02i%02i%02i" wide fullword
        $a7 = "[Cleared browsers logins and cookies.]" fullword
        $a8 = "[Chrome StoredLogins found, cleared!]" fullword
    condition:
        4 of them
}

