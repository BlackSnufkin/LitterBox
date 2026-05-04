rule Windows_Trojan_OnlyLogger_b9e88336 {
    meta:
        author = "Elastic Security"
        id = "b9e88336-9719-4f43-afc9-b0e6c7d72b6f"
        fingerprint = "5c8c98b250252d178c8dbad60bf398489d9396968e33b3e004219a4f323eeed8"
        creation_date = "2022-03-22"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.OnlyLogger"
        reference_sample = "69876ee4d89ba68ee86f1a4eaf0a7cb51a012752e14c952a177cd5ffd8190986"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "C:\\Users\\Ddani\\source\\repos\\onlyLogger\\Release\\onlyLogger.pdb" ascii fullword
        $b1 = "iplogger.org" ascii fullword
        $b2 = "NOT elevated" ascii fullword
        $b3 = "WinHttpSendRequest" ascii fullword
    condition:
        1 of ($a*) or all of ($b*)
}

rule Windows_Trojan_OnlyLogger_ec14d5f2 {
    meta:
        author = "Elastic Security"
        id = "ec14d5f2-5716-47f3-a7fb-98ec2d8679d1"
        fingerprint = "c69da3dfe0a464665759079207fbc0c82e690d812b38c83d3f4cd5998ecee1ff"
        creation_date = "2022-03-22"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.OnlyLogger"
        reference_sample = "f45adcc2aad5c0fd900df4521f404bc9ca71b01e3378a5490f5ae2f0c711912e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "KILLME" ascii fullword
        $a2 = "%d-%m-%Y %H" ascii fullword
        $a3 = "/c taskkill /im \"" ascii fullword
        $a4 = "\" /f & erase \"" ascii fullword
        $a5 = "/info.php?pub=" ascii fullword
    condition:
        all of them
}

