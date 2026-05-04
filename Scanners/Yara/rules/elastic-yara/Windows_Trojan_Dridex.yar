rule Windows_Trojan_Dridex_63ddf193 {
    meta:
        author = "Elastic Security"
        id = "63ddf193-31a6-4139-b452-960fe742da93"
        fingerprint = "7b4c5fde8e107a67ff22f3012200e56ec452e0a57a49edb2e06ee225ecfe228c"
        creation_date = "2021-08-07"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Dridex"
        reference_sample = "b1d66350978808577159acc7dc7faaa273e82c103487a90bf0d040afa000cb0d"
        severity = 90
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "snxhk.dll" ascii fullword
        $a2 = "LondLibruryA" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Dridex_c6f01353 {
    meta:
        author = "Elastic Security"
        id = "c6f01353-cf55-4eac-9f25-6f9cce3b7990"
        fingerprint = "fbdb230032e3655448d26a679afc612c79d33ac827bcd834e54fe5c05f04d828"
        creation_date = "2021-08-07"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Dridex"
        reference_sample = "739682ccb54170e435730c54ba9f7e09f32a3473c07d2d18ae669235dcfe84de"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 56 57 55 8B FA 85 C9 74 58 85 FF 74 54 0F B7 37 85 F6 75 04 }
    condition:
        all of them
}

