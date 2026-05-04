rule Windows_Trojan_IcedID_1cd868a6 {
    meta:
        author = "Elastic Security"
        id = "1cd868a6-d2ec-4c48-a69a-aaa6c7af876c"
        fingerprint = "3e76b3ac03c5268923cfd5d0938745d66cda273d436b83bee860250fdcca6327"
        creation_date = "2021-02-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
        reference_sample = "68dce9f214e7691db77a2f03af16a669a3cb655699f31a6c1f5aaede041468ff"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 24 2C B9 09 00 00 00 2A C2 2C 07 88 44 24 0F 0F B6 C3 6B C0 43 89 44 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_237e9fb6 {
    meta:
        author = "Elastic Security"
        id = "237e9fb6-b5fa-4747-af1f-533c76a5a639"
        fingerprint = "e2ea6d1477ce4132f123b6c00101a063f7bba7acf38be97ee8dca22cc90ed511"
        creation_date = "2021-02-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
        reference_sample = "b21f9afc6443548427bf83b5f93e7a54ac3af306d9d71b8348a6f146b2819457"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 60 8B 55 D4 3B D0 7E 45 83 F8 08 0F 4C 45 EC 3B D0 8D 3C 00 0F }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_f1ce2f0a {
    meta:
        author = "Elastic Security"
        id = "f1ce2f0a-0d34-46a4-8e42-0906adf4dc1b"
        fingerprint = "1940c4bf5d8011dc7edb8dde718286554ed65f9e96fe61bfa90f6182a4b8ca9e"
        creation_date = "2021-02-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
        reference_sample = "b21f9afc6443548427bf83b5f93e7a54ac3af306d9d71b8348a6f146b2819457"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8B C8 8B C6 F7 E2 03 CA 8B 54 24 14 2B D0 8B 44 24 14 89 54 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_08530e24 {
    meta:
        author = "Elastic Security"
        id = "08530e24-5b84-40a4-bc5c-ead74762faf8"
        fingerprint = "f2b5768b87eec7c1c9730cc99364cc90e87fd9201bf374418ad008fd70d321af"
        creation_date = "2021-03-21"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference_sample = "31db92c7920e82e49a968220480e9f130dea9b386083b78a79985b554ecdc6e4"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "c:\\ProgramData\\" ascii fullword
        $a2 = "loader_dll_64.dll" ascii fullword
        $a3 = "aws.amazon.com" wide fullword
        $a4 = "Cookie: __gads=" wide fullword
        $b1 = "LookupAccountNameW" ascii fullword
        $b2 = "GetUserNameA" ascii fullword
        $b3 = "; _gat=" wide fullword
        $b4 = "; _ga=" wide fullword
        $b5 = "; _u=" wide fullword
        $b6 = "; __io=" wide fullword
        $b7 = "; _gid=" wide fullword
        $b8 = "%s%u" wide fullword
        $b9 = "i\\|9*" ascii fullword
        $b10 = "WinHttpSetStatusCallback" ascii fullword
    condition:
        all of ($a*) and 5 of ($b*)
}

rule Windows_Trojan_IcedID_11d24d35 {
    meta:
        author = "Elastic Security"
        id = "11d24d35-6bff-4fac-83d8-4d152aa0be57"
        fingerprint = "155e5df0f3f598cdc21e5c85bcf21c1574ae6788d5f7e0058be823c71d06c21e"
        creation_date = "2022-02-16"
        last_modified = "2022-04-06"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference_sample = "b8d794f6449669ff2d11bc635490d9efdd1f4e92fcb3be5cdb4b40e4470c0982"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "C:\\Users\\user\\source\\repos\\anubis\\bin\\RELEASE\\loader_dll_64.pdb" ascii fullword
        $a2 = "loader_dll_64.dll" ascii fullword
    condition:
        1 of ($a*)
}

rule Windows_Trojan_IcedID_0b62e783 {
    meta:
        author = "Elastic Security"
        id = "0b62e783-5c1a-4377-8338-1c53194b8d01"
        fingerprint = "2f473fbe6338d9663808f1a3615cf8f0f6f9780fbce8f4a3c24f0ddc5f43dd4a"
        creation_date = "2022-04-06"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 89 44 95 E0 83 E0 07 8A C8 42 8B 44 85 E0 D3 C8 FF C0 42 89 44 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_91562d18 {
    meta:
        author = "Elastic Security"
        id = "91562d18-28a1-4349-9e4b-92ad165510c9"
        fingerprint = "024bbd15da6bc759e321779881b466b500f6364a1d67bbfdc950aedccbfbc022"
        creation_date = "2022-04-06"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 44 8B 4C 19 2C 4C 03 D6 74 1C 4D 85 C0 74 17 4D 85 C9 74 12 41 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_2086aecb {
    meta:
        author = "Elastic Security"
        id = "2086aecb-161b-4102-89c7-580fb9ac3759"
        fingerprint = "a8b6cbb3140ff3e1105bb32a2da67831917caccc4985c485bbfdb0aa50016d86"
        creation_date = "2022-04-06"
        last_modified = "2022-03-02"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 4C 8D 05 [4] 42 8A 44 01 ?? 42 32 04 01 88 44 0D ?? 48 FF C1 48 83 F9 20 72 ?? }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_48029e37 {
    meta:
        author = "Elastic Security"
        id = "48029e37-b392-4d53-b0de-2079f6a8a9d9"
        fingerprint = "375266b526fe14354550d000d3a10dde3f6a85e11f4ba5cab14d9e1f878de51e"
        creation_date = "2022-04-06"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 C1 E3 10 0F 31 48 C1 E2 ?? 48 0B C2 0F B7 C8 48 0B D9 8B CB 83 E1 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_56459277 {
    meta:
        author = "Elastic Security"
        id = "56459277-432c-437c-9350-f5efaa60ffca"
        fingerprint = "503bfa6800e0f4ff1a0b56eb8a145e67fa0f387c84aee7bd2eca3cf7074be709"
        creation_date = "2022-08-21"
        last_modified = "2023-03-02"
        description = "IcedID Gzip Variant Core"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference_sample = "21b1a635db2723266af4b46539f67253171399830102167c607c6dbf83d6d41c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "cookie.tar" ascii fullword
        $str2 = "passff.tar" ascii fullword
        $str3 = "\\sqlite64.dll" ascii fullword
        $str4 = "Cookie: session=" ascii fullword
        $str5 = "{0ccac395-7d1d-4641-913a-7558812ddea2}" ascii fullword
        $str6 = "mail_vault" wide fullword
        $seq_decrypt_payload = { 42 0F B6 04 32 48 FF C2 03 C8 C1 C1 ?? 48 3B D7 72 ?? 44 33 F9 45 33 C9 44 89 3C 3B 48 85 FF 74 ?? 41 0F B6 D1 44 8D 42 01 83 E2 03 41 83 E0 03 }
        $seq_compute_hash = { 0F B6 4C 14 ?? 48 FF C2 8B C1 83 E1 ?? 48 C1 E8 ?? 41 0F B7 04 41 66 89 03 48 8D 5B ?? 41 0F B7 0C 49 66 89 4B ?? 48 83 FA ?? 72 ?? 66 44 89 03 B8 }
        $seq_format_string = { C1 E8 ?? 44 0B D8 41 0F B6 D0 8B C1 C1 E2 ?? C1 E1 ?? 25 [4] 0B C1 41 C1 E8 ?? 41 0F B6 CA 41 0B D0 44 8B 44 24 ?? C1 E0 ?? C1 E1 ?? 41 C1 EB ?? 44 0B D8 41 C1 EA ?? 0F B7 44 24 ?? 41 0B CA }
        $seq_custom_ror = { 41 8A C0 41 8A D0 02 C0 0F B6 C8 8A C1 44 8B C1 34 ?? 84 D2 0F B6 C8 44 0F 48 C1 49 83 EB }
        $seq_string_decrypt = { 0F B7 44 24 ?? 0F B7 4C 24 ?? 3B C1 7D ?? 8B 4C 24 ?? E8 [4] 89 44 24 ?? 0F B7 44 24 ?? 48 8B 4C 24 ?? 0F B6 04 01 0F B6 4C 24 ?? 33 C1 0F B7 4C 24 ?? 48 8B 54 24 ?? 88 04 0A EB }
    condition:
        5 of ($str*) or 2 of ($seq_*)
}

rule Windows_Trojan_IcedID_7c1619e3 {
    meta:
        author = "Elastic Security"
        id = "7c1619e3-f94a-4a46-8a81-d5dd7a58c754"
        fingerprint = "ae21deaad74efaff5bec8c9010dc340118ac4c79e3bec190a7d3c3672a5a8583"
        creation_date = "2022-12-20"
        last_modified = "2023-02-01"
        description = "IcedID Injector Variant Loader "
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference_sample = "4f6de748628b8b06eeef3a5fabfe486bfd7aaa92f50dc5a8a8c70ec038cd33b1"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { C1 C9 0D 0F BE C0 03 C8 46 8A 06 84 C0 75 ?? 8B 74 24 ?? 81 F1 [4] 39 16 76 }
        $a2 = { D1 C8 F7 D0 D1 C8 2D 20 01 00 00 D1 C0 F7 D0 2D 01 91 00 00 }
        $a3 = { 8B 4E ?? FF 74 0B ?? 8B 44 0B ?? 03 C1 50 8B 44 0B ?? 03 46 ?? 50 E8 [4] 8B 46 ?? 8D 5B ?? 83 C4 0C 47 3B 78 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_d8b23cd6 {
    meta:
        author = "Elastic Security"
        id = "d8b23cd6-c20c-40c9-a8e9-80d68e709764"
        fingerprint = "d47af2b50d0fb07858538fdb9f53fee008b49c9b1d015e4593199407673e0e21"
        creation_date = "2023-01-03"
        last_modified = "2023-01-03"
        description = "IcedID VNC server"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference_sample = "bd4da2f84c29437bc7efe9599a3a41f574105d449ac0d9b270faaca8795153ab"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "User idle %u sec / Locked: %s / ScreenSaver: %s" wide
        $a2 = "No VNC HOOK" wide
        $a3 = "Webcam %u" wide
        $a4 = "rundll32.exe shell32.dll,#61"
        $a5 = "LAP WND"
        $a6 = "FG WND"
        $a7 = "CAP WND"
        $a8 = "HDESK Tmp" wide
        $a9 = "HDESK Bot" wide
        $a10 = "HDESK bot" wide
        $a11 = "CURSOR: %u, %u"
        $b1 = { 83 7C 24 ?? 00 75 ?? 83 7C 24 ?? 00 75 ?? [1] 8B 0D [4] 8B 44 24 }
    condition:
        6 of them
}

rule Windows_Trojan_IcedID_a2ca5f80 {
    meta:
        author = "Elastic Security"
        id = "a2ca5f80-85b1-4502-8794-b8b4ea1be482"
        fingerprint = "dfbacf63b91315e5acf168b57bf18283ba30f681f5b3d3835418d0d32d238854"
        creation_date = "2023-01-16"
        last_modified = "2023-04-23"
        description = "IcedID Injector Variant Core"
        threat_name = "Windows.Trojan.Icedid"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "EMPTY"
        $a2 = "CLEAR"
        $a3 = { 66 C7 06 6D 3D 83 C6 02 0F B6 05 [4] 50 68 34 73 00 10 56 FF D7 03 F0 66 C7 06 26 6A C6 46 ?? 3D 83 C6 03 }
        $a4 = { 8B 46 ?? 6A 00 FF 76 ?? F7 D8 FF 76 ?? 1B C0 FF 76 ?? 50 FF 76 ?? 53 FF 15 }
        $a5 = { 8D 44 24 ?? 89 7C 24 ?? 89 44 24 ?? 33 F6 B8 BB 01 00 00 46 55 66 89 44 24 ?? 89 74 24 ?? E8 [4] 89 44 24 ?? 85 C0 74 ?? 8B AC 24 }
        $a6 = { 8A 01 88 45 ?? 45 41 83 EE 01 75 ?? 8B B4 24 [4] 8B 7E }
        $a7 = { 53 E8 [4] 8B D8 30 1C 2F 45 59 3B EE 72 }
        $a8 = { 8B 1D [4] 33 D9 6A 00 53 52 E8 [4] 83 C4 0C 89 44 24 ?? 85 C0 0F 84 }
        $a9 = { C1 C9 0D 0F BE C0 03 C8 46 8A 06 }
    condition:
        4 of them
}

rule Windows_Trojan_IcedID_b8c59889 {
    meta:
        author = "Elastic Security"
        id = "b8c59889-2cc6-49c6-a81a-4bc36f3b1f6f"
        fingerprint = "2f15ed0bc186b83a298eb51b43f10aa46ce6654ea9312a9529d36fc4cff05d4c"
        creation_date = "2023-05-05"
        last_modified = "2023-06-13"
        description = "IcedID fork init loader"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference_sample = "a63d08cd53053bfda17b8707ab3a94cf3d6021097335dc40d5d211fb9faed045"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "{%0.8X-%0.4X-%0.4X-%0.4X-%0.4X%0.8X}" wide fullword
        $a2 = "\\1.bin" wide fullword
        $a3 = "c:\\ProgramData" wide fullword
        $a4 = "Loader.dll" ascii fullword
        $seq_crypto = { 83 E1 03 83 E0 03 48 8D 14 8A 41 8B 0C 80 4D 8D 04 80 41 0F B6 00 83 E1 07 02 02 41 32 04 29 41 88 04 19 49 FF C1 8B 02 }
    condition:
        4 of ($a*) or 1 of ($seq*)
}

rule Windows_Trojan_IcedID_81eff9a3 {
    meta:
        author = "Elastic Security"
        id = "81eff9a3-4c75-48a5-8160-718c9a2d1e14"
        fingerprint = "f764c4b2a562eb92a7326a45b180da7f930ffcc4f0b88bbd640c2fe7b71f82b6"
        creation_date = "2023-05-05"
        last_modified = "2023-06-13"
        description = "IcedID fork core bot loader"
        threat_name = "Windows.Trojan.IcedID"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference_sample = "96dacdf50d1db495c8395d7cf454aa3a824801cf366ac368fe496f89b5f98fe7"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "E:\\source\\anubis\\int-bot\\x64\\Release\\int-bot.pdb" ascii fullword
    condition:
        all of them
}

