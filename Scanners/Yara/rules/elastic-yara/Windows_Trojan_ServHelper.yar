rule Windows_Trojan_ServHelper_f4dee200 {
    meta:
        author = "Elastic Security"
        id = "f4dee200-5471-472b-a017-bfcc9c291cbe"
        fingerprint = "24e49a0c72e665a03cea66614481665eea962a0c6b0a2f9d459866d8070ab456"
        creation_date = "2022-03-22"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.ServHelper"
        reference_sample = "05d183430a7afe16a3857fc4e87568fcc18518e108823c37eabf0514660aa17c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 8B 45 78 48 63 4D 44 48 8B 55 48 4C 63 45 44 48 0F B7 44 48 FE 66 42 33 44 42 FE 66 89 45 42 48 8D 4D 28 48 0F B7 55 42 E8 ?? ?? ?? ?? 48 8B 4D 70 48 8B 55 28 E8 ?? ?? ?? ?? 83 45 44 01 83 EB 01 85 DB 75 ?? }
        $b = { 39 5D ?? 0F 8F ?? ?? ?? ?? 2B D8 83 C3 01 48 8B 45 ?? 48 63 4D ?? 66 83 7C 48 ?? 20 72 ?? 48 8B 45 ?? 48 63 4D ?? 66 83 7C 48 ?? 7F 76 ?? 48 8B 45 ?? 48 63 4D ?? 48 0F B7 44 48 ?? 66 83 E8 08 66 83 F8 07 77 ?? B2 01 8B C8 80 E1 7F D3 E2 48 0F B6 05 ?? ?? ?? ?? 84 C2 0F 95 C0 EB ?? 33 C0 84 C0 74 ?? 83 45 ?? 01 }
    condition:
        any of them
}

rule Windows_Trojan_ServHelper_370c5287 {
    meta:
        author = "Elastic Security"
        id = "370c5287-0e2f-4113-95b6-53d31671fa46"
        fingerprint = "a66134e9344cc5ba403fe0aad70e8a991c61582d6a5640c3b9e4a554374176a2"
        creation_date = "2022-03-24"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.ServHelper"
        reference_sample = "05d183430a7afe16a3857fc4e87568fcc18518e108823c37eabf0514660aa17c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 00 10 66 01 00 48 66 01 00 98 07 2B 00 50 66 01 00 95 66 01 }
    condition:
        all of them
}

