rule Windows_Trojan_Qbot_d91c1384 {
    meta:
        author = "Elastic Security"
        id = "d91c1384-839f-4062-8a8d-5cda931029ae"
        fingerprint = "1b47ede902b6abfd356236e91ed3e741cf1744c68b6bb566f0d346ea07fee49a"
        creation_date = "2021-07-08"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Qbot"
        reference = "https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern"
        reference_sample = "18ac3870aaa9aaaf6f4a5c0118daa4b43ad93d71c38bf42cb600db3d786c6dda"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { FE 8A 14 06 88 50 FF 8A 54 BC 11 88 10 8A 54 BC 10 88 50 01 47 83 }
    condition:
        all of them
}

rule Windows_Trojan_Qbot_7d5dc64a {
    meta:
        author = "Elastic Security"
        id = "7d5dc64a-a597-44ac-a0fd-cefffc5e9cff"
        fingerprint = "ab80d96a454e0aad56621e70be4d55f099c41b538a380feb09192d252b4db5aa"
        creation_date = "2021-10-04"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Qbot"
        reference = "https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern"
        reference_sample = "a2bacde7210d88675564106406d9c2f3b738e2b1993737cb8bf621b78a9ebf56"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%u.%u.%u.%u.%u.%u.%04x" ascii fullword
        $a2 = "stager_1.dll" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Qbot_6fd34691 {
    meta:
        author = "Elastic Security"
        id = "6fd34691-10e4-4a66-85ff-1b67ed3da4dd"
        fingerprint = "187fc04abcba81a2cbbe839adf99b8ab823cbf65993c8780d25e7874ac185695"
        creation_date = "2022-03-07"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Qbot"
        reference = "https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern"
        reference_sample = "0838cd11d6f504203ea98f78cac8f066eb2096a2af16d27fb9903484e7e6a689"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 75 C9 8B 45 1C 89 45 A4 8B 45 18 89 45 A8 8B 45 14 89 45 AC 8B }
        $a2 = "\\stager_1.obf\\Benign\\mfc\\" wide
    condition:
        any of them
}

rule Windows_Trojan_Qbot_3074a8d4 {
    meta:
        author = "Elastic Security"
        id = "3074a8d4-d93c-4987-9031-9ecd3881730d"
        fingerprint = "c233a0c24576450ce286d96126379b6b28d537619e853d860e2812f521b810ac"
        creation_date = "2022-06-07"
        last_modified = "2022-07-18"
        threat_name = "Windows.Trojan.Qbot"
        reference = "https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern"
        reference_sample = "c2ba065654f13612ae63bca7f972ea91c6fe97291caeaaa3a28a180fb1912b3a"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "qbot" wide
        $a2 = "stager_1.obf\\Benign\\mfc" wide
        $a3 = "common.obf\\Benign\\mfc" wide
        $a4 = "%u;%u;%u;"
        $a5 = "%u.%u.%u.%u.%u.%u.%04x"
        $a6 = "%u&%s&%u"
        $get_string1 = { 33 D2 8B ?? 6A 5A 5? F7 ?? 8B ?? 08 8A 04 ?? 8B 55 ?? 8B ?? 10 3A 04 ?? }
        $get_string2 = { 33 D2 8B ?? F7 75 F4 8B 45 08 8A 04 02 32 04 ?? 88 04 ?? ?? 83 ?? 01 }
        $set_key = { 8D 87 00 04 00 00 50 56 E8 ?? ?? ?? ?? 59 8B D0 8B CE E8 }
        $do_computer_use_russian_like_keyboard = { B9 FF 03 00 00 66 23 C1 33 C9 0F B7 F8 66 3B 7C 4D }
        $execute_each_tasks = { 8B 44 0E ?? 85 C0 74 ?? FF D0 EB ?? 6A 00 6A 00 6A 00 FF 74 0E ?? E8 ?? ?? ?? ?? 83 C4 10 }
        $generate_random_alpha_num_string = { 57 E8 ?? ?? ?? ?? 48 50 8D 85 ?? ?? ?? ?? 6A 00 50 E8 ?? ?? ?? ?? 8B 4D ?? 83 C4 10 8A 04 38 88 04 0E 46 83 FE 0C }
        $load_base64_dll_from_file_and_inject_into_targets = { 10 C7 45 F0 50 00 00 00 83 65 E8 00 83 7D F0 0B 73 08 8B 45 F0 89 }
    condition:
        6 of them
}

rule Windows_Trojan_Qbot_1ac22a26 {
    meta:
        author = "Elastic Security"
        id = "1ac22a26-ec88-4e88-8fe6-a092bbb61904"
        fingerprint = "22436c48bc775284d1f682eaeb650fd998302021342efc322c4ca40dd30f1a0d"
        creation_date = "2022-12-29"
        last_modified = "2023-02-01"
        threat_name = "Windows.Trojan.Qbot"
        reference = "https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern"
        reference_sample = "c2ba065654f13612ae63bca7f972ea91c6fe97291caeaaa3a28a180fb1912b3a"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "qbot" wide
        $a2 = "stager_1.obf\\Benign\\mfc" wide
        $a3 = "common.obf\\Benign\\mfc" wide
        $a4 = "%u;%u;%u"
        $a5 = "%u.%u.%u.%u.%u.%u.%04x"
        $a6 = "%u&%s&%u"
        $a7 = "mnjhuiv40"
        $a8 = "\\u%04X"
        $get_string1 = { 33 D2 8B ?? 6A ?? 5? F7 ?? 8B ?? 08 8A 04 ?? 8B 55 ?? 8B ?? 10 3A 04 }
        $get_string2 = { 8B C6 83 E0 ?? 8A 04 08 3A 04 1E 74 ?? 46 3B F2 72 }
        $get_string3 = { 8A 04 ?? 32 04 ?? 88 04 ?? 4? 83 ?? 01 }
        $set_key_1 = { 8D 87 00 04 00 00 50 56 E8 [4] 59 8B D0 8B CE E8 }
        $set_key_2 = { 59 6A 14 58 6A 0B 66 89 87 [0-1] 20 04 00 00 }
        $cccp_keyboard_0 = { 6A ?? 66 89 45 E? 58 6A ?? 66 89 45 E? 58 }
        $cccp_keyboard_1 = { 66 8B 84 9? ?? FE FF FF B9 FF 03 00 00 66 23 C1 33 ?? 0F B7 }
        $execute_each_tasks = { 8B 0D [4] 83 7C 0E 04 00 74 ?? 83 7C 0E 1C 00 74 ?? 8B 04 0E 85 C0 7E ?? 6B C0 3C }
        $generate_random_alpha_num_string = { 57 E8 [4] 48 50 8D 85 [4] 6A 00 50 E8 [4] 8B 4D ?? 83 C4 10 8A 04 38 88 04 0E 46 83 FE 0C }
        $load_and_inject_b64_dll_from_file = { 6B 45 FC 18 8B 4D F8 83 7C 01 04 00 76 ?? 6A 00 6B 45 FC 18 8B 4D F8 FF 74 01 10 6B 45 FC 18 }
        $decipher_rsrc_data = { F6 86 38 04 00 00 04 89 BE 2C 04 00 00 89 BE 28 04 00 00 [2-6] 8B 0B 8D 45 F? 83 65 F? 00 8B D7 50 E8 }
    condition:
        6 of them
}

