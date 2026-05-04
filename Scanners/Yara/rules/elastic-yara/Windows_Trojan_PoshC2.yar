rule Windows_Trojan_PoshC2_e2d3881e {
    meta:
        author = "Elastic Security"
        id = "e2d3881e-d849-4ec8-a560-000a9b29814f"
        fingerprint = "30a9161077a90068acf756dcc2354bd04186f87717e32cccdcacc9521c41ddde"
        creation_date = "2023-03-29"
        last_modified = "2023-04-23"
        threat_name = "Windows.Trojan.PoshC2"
        reference_sample = "7a718a4f74656346bd9a2e29e008705fc2b1c4d167a52bd4f6ff10b3f2cd9395"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Sharp_v4_x64.dll"
        $a2 = "Sharp_v4_x86_dll"
        $a3 = "Posh_v2_x64_Shellcode" wide
        $a4 = "Posh_v2_x86_Shellcode" wide
        $b1 = "kill-implant" wide
        $b2 = "run-dll-background" wide
        $b3 = "run-exe-background" wide
        $b4 = "TVqQAAMAAAAEAAAA"
    condition:
        1 of ($a*) and 1 of ($b*)
}

