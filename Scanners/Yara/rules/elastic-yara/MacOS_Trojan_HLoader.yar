rule MacOS_Trojan_HLoader_a3945baf {
    meta:
        author = "Elastic Security"
        id = "a3945baf-4708-4a0b-8a9b-1a5448ee4bc7"
        fingerprint = "a48ec79f07a6a53611b1d1e8fe938513ec0ea19344126e07331b48b028cb877e"
        creation_date = "2023-10-23"
        last_modified = "2023-10-23"
        threat_name = "MacOS.Trojan.HLoader"
        reference_sample = "2360a69e5fd7217e977123c81d3dbb60bf4763a9dae6949bc1900234f7762df1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $seq_main = { 74 ?? 49 89 C7 48 89 D8 4C 89 FF E8 ?? ?? ?? ?? 48 89 DF 31 F6 BA ?? ?? ?? ?? 4C 89 65 ?? 4D 89 F4 4C 89 F1 4C 8B 75 ?? 41 FF 56 ?? }
        $seq_exec = { 48 B8 00 00 00 00 00 00 00 E0 48 89 45 ?? 4C 8D 6D ?? BF 11 00 00 00 E8 ?? ?? ?? ?? 0F 10 45 ?? 0F 11 45 ?? 48 BF 65 78 65 63 46 69 6C 65 48 BE 20 65 72 72 6F 72 20 EF }
        $seq_rename = { 41 89 DE 84 DB 74 ?? 48 8B 7D ?? FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? }
    condition:
        2 of ($seq*)
}

