rule Windows_Trojan_Nighthawk_9f3a5abb {
    meta:
        author = "Elastic Security"
        id = "9f3a5abb-b329-44db-af71-d72eae2737ac"
        fingerprint = "a2c49831d048ba91951780f4295895eba3a15f489a39b26b7a27efbc81746e09"
        creation_date = "2022-11-24"
        last_modified = "2023-06-20"
        threat_name = "Windows.Trojan.Nighthawk"
        reference_sample = "b775a8f7629966592cc7727e2081924a7d7cf83edd7447aa60627a2b67d87c94"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $loader_build_iat0 = { B9 BF BF D1 D5 E8 ?? ?? ?? ?? BA 7C 75 84 91 [3-12] E8 ?? ?? ?? ?? BA 47 FB EB 2B [3-12] E8 ?? ?? ?? ?? BA 42 24 3D 39 [3-12] E8 ?? ?? ?? ?? BA E7 E9 EF EE [3-12] E8 ?? ?? ?? ?? BA 47 FD 36 2E [3-12] E8 ?? ?? ?? ?? BA 39 DE 19 3D [3-12] E8 ?? ?? ?? ?? BA 20 DF DB F7 [3-12] E8 ?? ?? ?? ?? BA 45 34 2A 41 [3-12] E8 ?? ?? ?? ?? BA 7D 1C 44 2E [3-12] E8 ?? ?? ?? ?? BA 7D 28 44 2E [3-12] E8 ?? ?? ?? ?? BA 94 36 65 8D [3-12] E8 ?? ?? ?? ?? }
        $loader_syscall_func = { 65 48 8B 04 25 30 00 00 00 48 8B 80 10 01 00 00 48 89 44 24 F0 65 48 8B 04 25 30 00 00 00 8B 40 68 49 89 CA FF 64 24 F0 }
        $seq_calc_offset = { 48 8D 0D ?? ?? ?? ?? 51 5A 48 81 C1 ?? ?? ?? ?? 48 81 C2 ?? ?? ?? ?? FF E2 }
        $seq_keying_registry = { BA ?? ?? ?? ?? 48 8B C8 48 8B D8 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 8B CB 4C 8B F0 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 8B CB 4C 8B F8 E8 ?? ?? ?? ?? 0F B6 4E ?? 48 8B D8 83 E9 ?? 74 ?? 83 F9 ?? 75 ?? 48 C7 C1 ?? ?? ?? ?? EB ?? }
        $seq_keying_hostname_user = { 40 53 48 83 EC ?? 8A 42 ?? 48 8B D9 3C ?? 75 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8D 53 ?? 48 8D 4B ?? C7 02 ?? ?? ?? ?? FF D0 85 C0 0F 95 C0 EB ?? }
        $seq_keying_file = { E8 ?? ?? ?? ?? 33 DB 48 8D 4E ?? 48 89 5C 24 ?? 45 33 C9 89 5C 24 ?? BA ?? ?? ?? ?? 4C 8B E0 89 5C 24 ?? 44 8D 43 ?? C7 44 24 ?? ?? ?? ?? ?? FF D7 48 8B F8 48 83 F8 ?? 74 ?? 8B 55 ?? 45 33 C9 45 33 C0 48 8B C8 }
        $seq_crypto_op = { 40 84 F6 74 ?? 48 8B C2 B9 04 00 00 00 F3 0F 6F 44 05 ?? F3 0F 6F 4C 05 ?? 48 8D 40 ?? 66 0F EF C8 F3 0F 7F 4C 05 ?? 48 83 E9 01 }
        $seq_byte_shift = { 48 83 C3 ?? 8D 4D ?? 48 03 CF 0F B6 41 ?? 0F B6 71 ?? C1 E6 08 0B F0 0F B6 41 ?? C1 E6 08 0B F0 0F B6 01 C1 E6 ?? 0B F0 41 3B 75 ?? 76 ?? B8 ?? ?? ?? ?? EB ?? }
    condition:
        ($loader_build_iat0 and $loader_syscall_func) or (2 of ($seq*))
}

rule Windows_Trojan_Nighthawk_2a2e3b9d {
    meta:
        author = "Elastic Security"
        id = "2a2e3b9d-e85f-43b6-9754-1aa7c9f6f978"
        fingerprint = "40912e8d6bd09754046598b1311080e0ec6e040cb1b9ca93003c6314725d4d45"
        creation_date = "2022-11-24"
        last_modified = "2023-06-20"
        threat_name = "Windows.Trojan.Nighthawk"
        reference_sample = "38881b87826f184cc91559555a3456ecf00128e01986a9df36a72d60fb179ccf"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $payload_bytes1 = { 66 C1 E0 05 66 33 D0 66 C1 E2 0A 66 0B D1 0F B7 D2 8B CA 0F B7 C2 C1 E9 02 33 CA 66 D1 E8 D1 E9 33 CA C1 E9 02 33 CA C1 E2 0F 83 E1 01 }
        $payload_bytes2 = { 48 8B D9 44 8B C2 41 C1 E0 0F 8B C2 F7 D0 48 8B F2 44 03 C0 41 8B C0 C1 E8 0C 41 33 C0 8D 04 80 8B C8 C1 E9 04 33 C8 44 69 C1 09 08 00 00 41 8B C0 C1 E8 10 44 33 C0 B8 85 1C A7 AA }
    condition:
        any of them
}

rule Windows_Trojan_Nighthawk_23489175 {
    meta:
        author = "Elastic Security"
        id = "23489175-ed41-4f43-ac85-b9ae3ffb55d9"
        fingerprint = "3ff9fe5ef10afa328025a6abd509af788a9b1d5ef73a379e3767b2a4291566a3"
        creation_date = "2023-06-14"
        last_modified = "2023-07-10"
        threat_name = "Windows.Trojan.Nighthawk"
        reference_sample = "697742d5dd071add40b700022fd30424cb231ffde223d21bd83a44890e06762f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $pdb = "C:\\Users\\Peter\\Desktop\\dev\\implant\\CommsChannel\\x64\\Release-ReflectiveDLL\\Implant.x64.pdb" ascii fullword
        $seq_str_decrypt = { 48 8B C3 48 83 7B ?? ?? 72 ?? 48 8B 03 0F BE 14 06 49 8B CF E8 ?? ?? ?? ?? 48 85 C0 74 ?? 49 2B C7 48 8D 0D ?? ?? ?? ?? 8A 0C 08 48 8B C3 48 83 7B ?? ?? 72 ?? 48 8B 03 88 0C 06 }
        $seq_hvnc = { BA 06 01 00 00 41 B9 00 00 20 A0 41 B8 20 00 00 00 48 8B CE FF 15 }
        $seq_pe_parsing = { 8B 44 24 ?? 48 6B C0 28 48 8B 4C 24 ?? 8B 44 01 ?? 48 8B 8C 24 ?? ?? ?? ?? 48 03 C8 48 8B C1 48 89 44 24 ?? 8B 44 24 ?? 48 6B C0 28 48 8B 4C 24 ?? 8B 44 01 ?? 89 44 24 ?? EB ?? }
        $seq_library_resolver = { 48 8B 84 24 ?? ?? ?? ?? 48 89 44 24 ?? 48 8B 44 24 ?? 48 63 40 ?? 48 8B 4C 24 ?? 48 03 C8 48 8B C1 48 89 44 24 ?? B8 ?? ?? ?? ?? 48 6B C0 ?? 48 8B 4C 24 ?? 8B 84 01 ?? ?? ?? ?? 89 44 24 ?? 83 7C 24 ?? ?? 75 ?? 33 C0 E9 ?? ?? ?? ?? }
        $seq_disk_info = { 4C 8B A3 B0 00 00 00 48 8B BB A8 00 00 00 49 3B FC 0F 84 ?? ?? ?? ?? 48 8D B3 D8 00 00 00 4C 8D B3 F0 00 00 00 4C 8D BB C0 00 00 00 45 33 ED }
        $seq_keyname = { 8B 4B 08 C1 E1 08 0B 4B 04 C1 E1 10 41 B8 40 00 00 00 48 8D 95 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }
        $seq_tcptable = { 41 BF 02 00 00 00 41 3B FF 74 ?? 83 FF 17 41 8B C7 75 ?? B8 08 00 00 00 }
    condition:
        (1 of ($pdb)) or (2 of ($seq*))
}

