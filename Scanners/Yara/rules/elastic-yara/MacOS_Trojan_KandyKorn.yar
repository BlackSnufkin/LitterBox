rule MacOS_Trojan_KandyKorn_a7bb6944 {
    meta:
        author = "Elastic Security"
        id = "a7bb6944-90fa-40ba-840c-f044f12dcb39"
        fingerprint = "f2b2ebc056c79448b077dce140b2a73d6791b61ddc8bf21d4c565c95f5de49e7"
        creation_date = "2023-10-23"
        last_modified = "2023-10-23"
        threat_name = "MacOS.Trojan.KandyKorn"
        reference = "https://www.elastic.co/security-labs/elastic-catches-dprk-passing-out-kandykorn"
        reference_sample = "51dd4efcf714e64b4ad472ea556bf1a017f40a193a647b9e28bf356979651077"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $str_1 = "resp_file_dir"
        $str_2 = "resp_cfg_set"
        $str_3 = "resp_proc_kill"
        $str_4 = "/com.apple.safari.ck" ascii fullword
        $str_5 = "/chkupdate.XXX" ascii fullword
        $seq_file_dir = { 83 7D ?? ?? 0F 8E ?? ?? ?? ?? 48 63 45 ?? 48 83 C0 ?? 48 8B 4D ?? 0F B7 49 ?? 48 01 C8 48 83 C0 01 48 3D 00 00 0A 00 0F 86 ?? ?? ?? ?? }
        $seq_cmd_send = { 8B 45 ?? 83 F8 ?? 0F 8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 78 ?? 48 8B 70 ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
        $seq_cfg_get = { 8B 45 ?? 83 F8 ?? 0F 8C ?? ?? ?? ?? 48 8B 45 ?? 48 8B 38 48 8B 70 ?? 8B 55 ?? E8 ?? ?? ?? ?? 89 45 ?? E9 ?? ?? ?? ?? }
        $seq_proc_list = { 48 83 F8 ?? 0F 85 ?? ?? ?? ?? 8B 4D ?? 48 8B 85 ?? ?? ?? ?? 89 48 ?? 8B 4D ?? 48 8B 85 ?? ?? ?? ?? 89 48 ?? 8B 4D ?? 48 8B 85 ?? ?? ?? ?? }
        $rc4_key = { D9 F9 36 CE 62 8C 3E 5D 9B 36 95 69 4D 1C DE 79 E4 70 E9 38 06 4D 98 FB F4 EF 98 0A 55 58 D1 C9 0C 7E 65 0C 23 62 A2 1B 91 4A BD 17 3A BA 5C 0E 58 37 C4 7B 89 F7 4C 5B 23 A7 29 4C C1 CF D1 1B }
    condition:
        4 of ($str*) or 3 of ($seq*) or $rc4_key
}

