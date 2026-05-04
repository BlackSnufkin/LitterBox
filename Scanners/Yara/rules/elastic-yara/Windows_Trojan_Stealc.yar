rule Windows_Trojan_Stealc_b8ab9ab5 {
    meta:
        author = "Elastic Security"
        id = "b8ab9ab5-5731-4651-b982-03ad8fe347fb"
        fingerprint = "49253b1d1e39ba25b2d3b622d00633b9629715e65e1537071b0f3b0318b7db12"
        creation_date = "2024-03-13"
        last_modified = "2024-03-21"
        threat_name = "Windows.Trojan.Stealc"
        reference_sample = "0d1c07c84c54348db1637e21260dbed09bd6b7e675ef58e003d0fe8f017fd2c8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_str_decrypt = { 55 8B EC 83 EC ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 83 C0 ?? 50 }
        $seq_lang_check = { 81 E9 19 04 00 00 89 4D ?? 83 7D ?? ?? 77 ?? 8B 55 ?? 0F B6 82 ?? ?? ?? ?? FF 24 85 ?? ?? ?? ?? }
        $seq_mem_check_constant = { 72 09 81 7D F8 57 04 00 00 73 08 }
        $seq_hwid_algo = { 8B 08 69 C9 0B A3 14 00 81 E9 51 75 42 69 8B 55 08 }
        $str1 = "- Country: ISO?" ascii fullword
        $str2 = "%d/%d/%d %d:%d:%d" ascii fullword
        $str3 = "%08lX%04lX%lu" ascii fullword
        $str4 = "\\Outlook\\accounts.txt" ascii fullword
        $str5 = "/c timeout /t 5 & del /f /q" ascii fullword
    condition:
        (2 of ($seq*) or 4 of ($str*))
}

rule Windows_Trojan_Stealc_a2b71dc4 {
    meta:
        author = "Elastic Security"
        id = "a2b71dc4-4041-4c1f-b546-a2b6947702d1"
        fingerprint = "9eeb13fededae39b8a531fa5d07eaf839b56a1c828ecd11322c604962e8b1aec"
        creation_date = "2024-03-13"
        last_modified = "2024-03-21"
        threat_name = "Windows.Trojan.Stealc"
        reference_sample = "0d1c07c84c54348db1637e21260dbed09bd6b7e675ef58e003d0fe8f017fd2c8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_1 = { 8B C6 C1 E8 02 33 C6 D1 E8 33 C6 C1 E8 02 33 C6 83 E0 01 A3 D4 35 61 00 C1 E0 0F 66 D1 E9 66 0B C8 }
        $seq_2 = { FF D3 8B 4D ?? E8 [4] 6A ?? 33 D2 5F 8B C8 F7 F7 85 D2 74 ?? }
        $seq_3 = { 33 D2 8B F8 59 F7 F1 8B C7 3B D3 76 04 2B C2 03 C1 }
        $seq_4 = { 6A 7C 58 66 89 45 FC 8D 45 F0 50 8D 45 FC 50 FF 75 08 C7 45 F8 01 }
    condition:
        2 of ($seq*)
}

rule Windows_Trojan_Stealc_5d3f297c {
    meta:
        author = "Elastic Security"
        id = "5d3f297c-b812-401a-8671-2e00369cd6f2"
        fingerprint = "ff90bfcb28bb3164fb11da5f35f289af679805f7e4047e48d97ae89e5b820dcd"
        creation_date = "2024-03-05"
        last_modified = "2024-06-13"
        threat_name = "Windows.Trojan.Stealc"
        reference_sample = "885c8cd8f7ad93f0fd43ba4fb7f14d94dfdee3d223715da34a6e2fbb4d25b9f4"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 08 C7 45 F8 00 00 00 00 83 7D 08 00 74 4A 83 7D 0C 00 74 44 8B 45 0C 83 C0 01 50 6A 40 ?? ?? ?? ?? ?? ?? 89 45 F8 83 7D F8 00 74 2C C7 45 FC 00 00 00 00 EB 09 8B 4D FC 83 C1 01 }
    condition:
        all of them
}

rule Windows_Trojan_Stealc_41db1d4d {
    meta:
        author = "Elastic Security"
        id = "41db1d4d-d19f-441b-82c3-5ae94ef2baab"
        fingerprint = "be16274bf7c8fe038b19700aaae47ff0ffcf9cbb98ac93adb7e228c5854b782c"
        creation_date = "2025-07-16"
        last_modified = "2025-09-19"
        threat_name = "Windows.Trojan.Stealc"
        reference_sample = "a68bc167669c7c98b6742209acea111be61e6002aa652a7b8116af47b284b084"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "C:\\builder_v2\\stealc\\json.h" wide fullword
        $a2 = "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX" fullword
        $a3 = "/c timeout /t 5 & del /f /q \"" fullword
        $b1 = { 0F B7 C8 81 E9 19 04 00 00 74 14 83 E9 09 74 0F 83 E9 01 74 0A 83 E9 1C 74 05 83 F9 04 75 08 33 C9 FF }
        $b2 = { 22 74 6F 74 61 6C 5F 70 61 72 74 73 22 3A 20 00 2C 20 00 00 00 00 00 00 22 70 61 72 74 5F 69 6E 64 65 78 22 3A 20 }
        $b3 = { 48 89 5C 24 10 57 48 83 EC ?? 0F 57 C0 48 8D 3D [3] 00 0F 11 01 48 C7 41 10 00 00 00 00 48 8B D9 48 C7 41 18 0F 00 00 00 C6 01 00 8A 05 [3] 00 EB }
    condition:
        3 of them
}

