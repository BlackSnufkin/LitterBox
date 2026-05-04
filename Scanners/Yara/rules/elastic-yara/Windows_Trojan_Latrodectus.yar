rule Windows_Trojan_Latrodectus_841ff697 {
    meta:
        author = "Elastic Security"
        id = "841ff697-f389-497a-b813-3b9e19cba26e"
        fingerprint = "66285582e63dd5e444fd18a5d3bafcd00eefbf5f7fda3ee72045e92707a3976c"
        creation_date = "2024-03-13"
        last_modified = "2025-05-27"
        threat_name = "Windows.Trojan.Latrodectus"
        reference_sample = "aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $Str1 = { 48 83 EC 38 C6 44 24 20 73 C6 44 24 21 63 C6 44 24 22 75 C6 44 24 23 62 C6 44 24 24 }
        $crc32_loadlibrary = { 48 89 44 24 40 EB 02 EB 90 48 8B 4C 24 20 E8 ?? ?? FF FF 48 8B 44 24 40 48 81 C4 E8 02 00 00 C3 }
        $delete_self = { 44 24 68 BA 03 00 00 00 48 8B 4C 24 48 FF 15 ED D1 00 00 85 C0 75 14 48 8B 4C 24 50 E8 ?? ?? 00 00 B8 FF FF FF FF E9 A6 00 }
        $Str4 = { 89 44 24 44 EB 1F C7 44 24 20 00 00 00 00 45 33 C9 45 33 C0 33 D2 48 8B 4C 24 48 FF 15 7E BB 00 00 89 44 24 44 83 7C 24 44 00 75 02 EB 11 48 8B 44 24 48 EB 0C 33 C0 85 C0 0F 85 10 FE FF FF 33 }
        $handler_check = { 83 BC 24 D8 01 00 00 12 74 36 83 BC 24 D8 01 00 00 0E 74 2C 83 BC 24 D8 01 00 00 0C 74 22 83 BC 24 D8 01 00 00 0D 74 18 83 BC 24 D8 01 00 00 0F 74 0E 83 BC 24 D8 01 00 00 04 0F 85 44 02 00 00 }
        $hwid_calc = { 48 89 4C 24 08 48 8B 44 24 08 69 00 0D 66 19 00 48 8B 4C 24 08 89 01 48 8B 44 24 08 8B 00 C3 }
        $string_decrypt = { 89 44 24 ?? 48 8B 44 24 ?? 0F B7 40 ?? 8B 4C 24 ?? 33 C8 8B C1 66 89 44 24 ?? 48 8B 44 24 ?? 48 83 C0 ?? 48 89 44 24 ?? 33 C0 66 89 44 24 ?? EB }
        $campaign_fnv = { 48 03 C8 48 8B C1 48 39 44 24 08 73 1E 48 8B 44 24 08 0F BE 00 8B 0C 24 33 C8 8B C1 89 04 24 69 04 24 93 01 00 01 89 04 24 EB BE }
        $sleep = { 81 BC 24 ?? ?? ?? ?? 08 07 00 00 7D ?? B9 64 00 00 00 E8 }
        $timeout = { B9 96 00 00 00 F7 F1 8B C2 05 C2 01 00 00 69 C0 E8 03 00 00 }
    condition:
        3 of them
}

