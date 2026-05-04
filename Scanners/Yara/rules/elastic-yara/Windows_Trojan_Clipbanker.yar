rule Windows_Trojan_Clipbanker_7efaef9f {
    meta:
        author = "Elastic Security"
        id = "7efaef9f-51cd-4fea-a48d-fa9d39cb735e"
        fingerprint = "fe0ec44f8707cd03f845dbea4ff5bb1b699db1b69b75f0365168a75cc8bb68a3"
        creation_date = "2022-02-28"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Clipbanker"
        reference_sample = "02b06acb113c31f5a2ac9c99f9614e0fab0f78afc5ae872e46bae139c2c9b1f6"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "C:\\Users\\youar\\Desktop\\Allcome\\Source code\\Build\\Release\\Build.pdb" ascii fullword
        $b1 = "https://steamcommunity.com/tradeoffer" ascii fullword
        $b2 = "/Create /tn NvTmRep_CrashReport3_{B2FE1952-0186} /sc MINUTE /tr %s" ascii fullword
        $b3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0" ascii fullword
        $b4 = "ProcessHacker.exe" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Clipbanker_b60a50b8 {
    meta:
        author = "Elastic Security"
        id = "b60a50b8-91a4-49a7-bd05-fa4cc1dee1ac"
        fingerprint = "097bb88d8482a4915c19affc82750c7ee225b89f2611ea654cfc3c044aae0738"
        creation_date = "2022-02-28"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Clipbanker"
        reference_sample = "02b06acb113c31f5a2ac9c99f9614e0fab0f78afc5ae872e46bae139c2c9b1f6"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 40 66 0F F8 C1 0F 11 40 A0 0F 10 84 15 08 FF FF FF 83 C2 40 }
    condition:
        all of them
}

rule Windows_Trojan_Clipbanker_f9f9e79d {
    meta:
        author = "Elastic Security"
        id = "f9f9e79d-ce71-4b6c-83e0-ac6e06252c25"
        fingerprint = "ec985e1273d8ff52ea7f86271a96db01633402facf8d140d11b82e5539e4b5fd"
        creation_date = "2022-04-23"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.Clipbanker"
        reference_sample = "0407e8f54490b2a24e1834d99ec0452f217499f1e5a64de3d28439d71d16d43c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 7E 7E 0F B7 04 77 83 F8 41 74 69 83 F8 42 74 64 83 F8 43 74 5F 83 }
    condition:
        all of them
}

rule Windows_Trojan_Clipbanker_787b130b {
    meta:
        author = "Elastic Security"
        id = "787b130b-6382-42f0-8822-fce457fa940d"
        fingerprint = "15f3c7d5f25982a02a6bca0b550b3b65e1e21efa5717a1ea0c13dfe46b8f2699"
        creation_date = "2022-04-24"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.Clipbanker"
        reference_sample = "0407e8f54490b2a24e1834d99ec0452f217499f1e5a64de3d28439d71d16d43c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $mutex_setup = { 55 8B EC 83 EC ?? 53 56 57 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 3D ?? ?? ?? ?? 75 ?? 6A ?? FF 15 ?? ?? ?? ?? }
        $new_line_check = { 0F B7 C2 89 45 ?? 0F B7 C2 83 F8 0A 74 ?? BA 0D 0A 00 00 66 3B C2 74 ?? 83 F8 0D 74 ?? 83 F8 20 74 ?? 83 F8 09 74 ?? }
        $regex1 = { 0F B7 C2 89 45 ?? 0F B7 C2 83 F8 0A 74 ?? BA 0D 0A 00 00 66 3B C2 74 ?? 83 F8 0D 74 ?? 83 F8 20 74 ?? 83 F8 09 74 ?? }
        $regex2 = { 6A 34 59 66 39 0E 75 ?? 0F B7 46 ?? 6A 30 5A 83 F8 41 74 ?? 83 F8 42 74 ?? 66 3B C2 74 ?? 83 F8 31 74 ?? 83 F8 32 74 ?? 83 F8 33 74 ?? 66 3B C1 74 ?? 83 F8 35 74 ?? 83 F8 36 74 ?? 83 F8 37 74 ?? 83 F8 38 74 ?? 83 F8 39 75 ?? }
        $regex3 = { 56 8B F1 56 FF 15 ?? ?? ?? ?? 83 F8 5F 0F 85 ?? ?? ?? ?? 6A 38 59 66 39 0E 75 ?? 0F B7 46 ?? 6A 30 5A 83 F8 41 74 ?? 83 F8 42 74 ?? 66 3B C2 74 ?? 83 F8 31 74 ?? 83 F8 32 74 ?? 83 F8 33 74 ?? 83 F8 34 74 ?? 83 F8 35 74 ?? 83 F8 36 74 ?? 83 F8 37 74 ?? 66 3B C1 74 ?? 83 F8 39 75 ?? }
    condition:
        any of them
}

