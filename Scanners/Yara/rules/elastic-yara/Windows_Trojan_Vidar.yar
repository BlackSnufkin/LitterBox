rule Windows_Trojan_Vidar_9007feb2 {
    meta:
        author = "Elastic Security"
        id = "9007feb2-6ad1-47b6-bae2-3379d114e4f1"
        fingerprint = "8416b14346f833264e32c63253ea0b0fe28e5244302b2e1b266749c543980fe2"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "34c0cb6eaf2171d3ab9934fe3f962e4e5f5e8528c325abfe464d3c02e5f939ec"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { E8 53 FF D6 50 FF D7 8B 45 F0 8D 48 01 8A 10 40 3A D3 75 F9 }
    condition:
        all of them
}

rule Windows_Trojan_Vidar_114258d5 {
    meta:
        author = "Elastic Security"
        id = "114258d5-f05e-46ac-914b-1a7f338ccf58"
        fingerprint = "9b4f7619e15398fcafc622af821907e4cf52964c55f6a447327738af26769934"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "34c0cb6eaf2171d3ab9934fe3f962e4e5f5e8528c325abfe464d3c02e5f939ec"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "BinanceChainWallet" fullword
        $a2 = "*wallet*.dat" fullword
        $a3 = "SOFTWARE\\monero-project\\monero-core" fullword
        $b1 = "CC\\%s_%s.txt" fullword
        $b2 = "History\\%s_%s.txt" fullword
        $b3 = "Autofill\\%s_%s.txt" fullword
    condition:
        1 of ($a*) and 1 of ($b*)
}

rule Windows_Trojan_Vidar_32fea8da {
    meta:
        author = "Elastic Security"
        id = "32fea8da-b381-459c-8bf4-696388b8edcc"
        fingerprint = "ebcced7b2924cc9cfe9ed5b5f84a8959e866a984f2b5b6e1ec5b1dd096960325"
        creation_date = "2023-05-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "6f5c24fc5af2085233c96159402cec9128100c221cb6cb0d1c005ced7225e211"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 4F 4B 58 20 57 65 62 33 20 57 61 6C 6C 65 74 }
        $a2 = { 8B E5 5D C3 5E B8 03 00 00 00 5B 8B E5 5D C3 5E B8 08 00 00 }
        $a3 = { 83 79 04 00 8B DE 74 08 8B 19 85 DB 74 62 03 D8 8B 03 85 C0 }
    condition:
        all of them
}

rule Windows_Trojan_Vidar_c374cd85 {
    meta:
        author = "Elastic Security"
        id = "c374cd85-714b-47c5-8645-cc7918fa2ff1"
        fingerprint = "4936566b7f3f8250b068aa8e4a9b745c3e9ce2fa35164a94e77b31068d3d6ebf"
        creation_date = "2024-01-31"
        last_modified = "2024-10-14"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "1c677585a8b724332849c411ffe2563b2b753fd6699c210f0720352f52a6ab72"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 0C 53 8B 5E 74 39 9E 44 01 00 00 75 07 33 C0 E9 88 00 00 00 57 8B BE E0 00 00 00 85 FF 74 79 8B 8E E4 00 00 00 85 C9 74 6F 8B 86 44 01 00 00 8B D0 03 C7 8D 4C 01 F8 2B D3 89 4D }
    condition:
        all of them
}

rule Windows_Trojan_Vidar_65d3d7e5 {
    meta:
        author = "Elastic Security"
        id = "65d3d7e5-2a5f-4434-8578-6ccaa4528086"
        fingerprint = "249ba1f0078792d3b4cb61b6c7e902b327305a1398a3c88f1720ad8e6c30fe57"
        creation_date = "2024-10-14"
        last_modified = "2024-10-24"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "83d7c2b437a5cbb314c457d3b7737305dadb2bc02d6562a98a8a8994061fe929"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_1 = "avghooka.dll" wide fullword
        $str_2 = "api_log.dll" wide fullword
        $str_3 = "babyfox.dll" ascii fullword
        $str_4 = "vksaver.dll" ascii fullword
        $str_5 = "delays.tmp" wide fullword
        $str_6 = "\\Monero\\wallet.keys" ascii fullword
        $str_7 = "wallet_path" ascii fullword
        $str_8 = "Hong Lee" ascii fullword
        $str_9 = "milozs" ascii fullword
    condition:
        6 of them
}

rule Windows_Trojan_Vidar_5e3e5c75 {
    meta:
        author = "Elastic Security"
        id = "5e3e5c75-00a6-4dca-ac29-1a4d3554b9bd"
        fingerprint = "6a21d58bd025d08b40c64fd38df8af637bc97938b268143427aaa96c79a8caa7"
        creation_date = "2025-12-16"
        last_modified = "2026-02-02"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "0f8976f8b0f6f717ffdfb22cfc1620eee53ce462975bb270929bff3497d22beb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "%DRIVE_FIXED%" fullword
        $e = "%DRIVE_REMOVABLE%" fullword
        $d = "_0.indexeddb.leveldb" fullword
        $c = "key4.db" fullword
    condition:
        all of them
}

rule Windows_Trojan_Vidar_4ed00a37 {
    meta:
        author = "Elastic Security"
        id = "4ed00a37-9101-4c54-ad42-06e81051be69"
        fingerprint = "92f3a503d66bc9873691a36f8259aee86948e0b9594e6b8c492b970d9d587500"
        creation_date = "2025-12-16"
        last_modified = "2026-02-02"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "0f8976f8b0f6f717ffdfb22cfc1620eee53ce462975bb270929bff3497d22beb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8A 1C 32 44 30 C3 88 1C 31 }
        $b = { 42 8A 1C 1A 44 30 C3 42 88 1C 19 }
    condition:
        all of them
}

rule Windows_Trojan_Vidar_540563cf {
    meta:
        author = "Elastic Security"
        id = "540563cf-c0d4-4720-b465-85469366a600"
        fingerprint = "6a804cc2bf7b71497cd70c653763bd2359d1716921adb2943425f03bd2521da1"
        creation_date = "2026-01-30"
        last_modified = "2026-03-17"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "5293d0caca719e681358502968b75c2209e78d2822975a9ab54cec10f0f4dc57"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 8D 15 ?? ?? FF FF 41 B8 00 01 00 00 E8 ?? ?? ?? 00 48 8D 0D }
        $b = { 48 00 6F 00 73 00 74 00 4E 00 61 00 6D 00 65 00 00 00 55 00 73 00 65 00 72 00 4E 00 61 00 6D 00 65 00 00 00 50 00 61 00 73 00 73 00 77 00 6F 00 72 00 64 00 00 00 50 00 6F 00 72 00 74 00 4E 00 75 00 6D 00 62 00 65 00 72 }
        $c = { 8D 48 01 0F AF C8 83 E1 01 74 02 EB FE C3 }
        $d = { 31 C0 41 80 3C 24 31 0F 94 C0 89 86 14 04 00 00 }
        $e = { 31 C0 41 80 3C 24 31 0F 94 C0 89 86 38 04 00 00 }
        $f = { 45 31 C0 41 80 3C 24 31 41 0F 94 C0 44 89 86 24 04 00 00 }
        $g = "File Grabber Rules" fullword
        $h = "Wallet Rules" fullword
        $i = "%08lX%04lX%08lX" fullword
    condition:
        5 of them
}

