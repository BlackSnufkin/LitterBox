rule Windows_Generic_Threat_bc6ae28d {
    meta:
        author = "Elastic Security"
        id = "bc6ae28d-050b-43d9-ba57-82fb37a2bc91"
        fingerprint = "40a45e5b109a9b48cecd95899ff6350af5d28deb1c6f3aa4f0363ed3abf62bf7"
        creation_date = "2023-12-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ce00873eb423c0259c18157a07bf7fd9b07333e528a5b9d48be79194310c9d97"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 24 83 79 08 00 75 19 DD 01 8D 45 DC 50 51 51 DD 1C 24 E8 DB FC FF FF 85 C0 74 05 8B 45 F0 C9 C3 83 C8 FF C9 C3 55 8B EC 83 EC 24 83 79 08 00 75 19 DD 01 8D 45 DC 50 51 51 DD 1C }
    condition:
        all of them
}

rule Windows_Generic_Threat_ce98c4bc {
    meta:
        author = "Elastic Security"
        id = "ce98c4bc-22bb-4c2b-bced-8fc36bd3a2f0"
        fingerprint = "d0849208c71c1845a6319052474549dba8514ecf7efe6185c1af22ad151bdce7"
        creation_date = "2023-12-17"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "950e8a29f516ef3cf1a81501e97fbbbedb289ad9fb93352edb563f749378da35"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 4D 65 73 73 61 67 65 50 61 63 6B 4C 69 62 2E 4D 65 73 73 61 67 65 50 61 63 6B }
        $a2 = { 43 6C 69 65 6E 74 2E 41 6C 67 6F 72 69 74 68 6D }
    condition:
        all of them
}

rule Windows_Generic_Threat_0cc1481e {
    meta:
        author = "Elastic Security"
        id = "0cc1481e-d666-4443-852c-679ef59e4ee4"
        fingerprint = "3dac71f8cbe7cb12066e91ffb6da6524891654fda249fa5934946fd5a2120360"
        creation_date = "2023-12-17"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "6ec7781e472a6827c1406a53ed4699407659bd57c33dd4ab51cabfe8ece6f23f"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 C4 A8 53 56 57 8B FA 8B D8 8B 43 28 3B 78 10 0F 84 B4 00 00 00 8B F0 85 FF 75 15 83 7E 04 01 75 0F 8B 46 10 E8 03 A7 FF FF 33 C0 89 46 10 EB 7C 8B C3 E8 B5 F3 FF FF 8B C3 E8 BE F3 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2507c37c {
    meta:
        author = "Elastic Security"
        id = "2507c37c-a0ef-47e0-a02a-3e28f4655715"
        fingerprint = "b20b76f19d21730b6e32d1468f0e14ee9d6f9f07b9692fb6dec76605d9b967e2"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "04296258f054a958f0fd013b3c6a3435280b28e9a27541463e6fc9afe30363cc"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 8B 45 14 56 57 33 FF 3B C7 74 47 39 7D 08 75 1B E8 B2 2B 00 00 6A 16 5E 89 30 57 57 57 57 57 E8 3B 2B 00 00 83 C4 14 8B C6 EB 29 39 7D 10 74 E0 39 45 0C 73 0E E8 8D 2B 00 00 6A 22 59 }
    condition:
        all of them
}

rule Windows_Generic_Threat_e052d248 {
    meta:
        author = "Elastic Security"
        id = "e052d248-32f2-4d51-b42d-468a09e06daa"
        fingerprint = "ccfbcb9271b1ce99b814cf9e3a4776e9501035166824beaf39d4b8cd03446ef3"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ed2bbc0d120665044aacb089d8c99d7c946b54d1b08a078aebbb3b91f593da6e"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 64 A1 00 00 00 00 6A FF 68 4F 5A 54 00 50 64 89 25 00 00 00 00 6A 02 68 24 D0 58 00 E8 FF 65 10 00 C7 45 FC FF FF FF FF 68 10 52 55 00 E8 F7 72 10 00 8B 4D F4 83 C4 0C 64 89 0D 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2bb7fbe3 {
    meta:
        author = "Elastic Security"
        id = "2bb7fbe3-2add-4ae9-adbf-5f043475d879"
        fingerprint = "e20c20c61768bd936cc18df56d7ec12d92745b6534ac8149bf367d6ad62fa8bd"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "65cc8704c0e431589d196eadb0ac8a19151631c8d4ab7375d7cb18f7b763ba7b"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 14 68 B6 32 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 30 53 56 57 89 65 EC C7 45 F0 C0 15 40 00 33 F6 89 75 F4 89 75 F8 89 75 E0 89 75 DC 89 75 D8 6A 01 FF 15 AC 10 }
    condition:
        all of them
}

rule Windows_Generic_Threat_994f2330 {
    meta:
        author = "Elastic Security"
        id = "994f2330-ce61-4c23-b100-7df3feaeb078"
        fingerprint = "4749717da2870a3942d7a3aa7e2809c4b9dc783a484bfcd2ce7416ae67164a26"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0a30cb09c480a2659b6f989ac9fe1bfba1802ae3aad98fa5db7cdd146fee3916"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 0C 8B 55 08 85 D2 0F 84 C7 00 00 00 8B 42 3C 83 7C 10 74 10 8D 44 10 18 0F 82 B5 00 00 00 83 78 64 00 0F 84 AB 00 00 00 8B 4D 0C 8B 40 60 C1 E9 10 03 C2 66 85 C9 75 14 0F B7 4D }
    condition:
        all of them
}

rule Windows_Generic_Threat_bf7aae24 {
    meta:
        author = "Elastic Security"
        id = "bf7aae24-f89a-4cc6-9a15-fc29aa80af98"
        fingerprint = "9304e9069424d43613ef9a5484214d0e3620245ef9ae64bae7d825f5f69d90c0"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "6dfc63894f15fc137e27516f2d2a56514c51f25b41b00583123142cf50645e4e"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 33 F6 44 8B EE 48 89 74 24 20 8B EE 48 89 B4 24 A8 00 00 00 44 8B F6 48 89 74 24 28 44 8B E6 E8 BF FF FF FF 4C 8B F8 8D 5E 01 B8 4D 5A 00 00 66 41 39 07 75 1B 49 63 57 3C 48 8D 4A }
    condition:
        all of them
}

rule Windows_Generic_Threat_d542e5a5 {
    meta:
        author = "Elastic Security"
        id = "d542e5a5-0648-40de-8b70-9f78f9bd1443"
        fingerprint = "62d3edc282cedd5a6464b92725a3916e3bdc75e8eb39db457d783cb27afa3aec"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "3fc4ae7115e0bfa3fc6b75dcff867e7bf9ade9c7f558f31916359d37d001901b"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 56 FF 75 08 8B F1 E8 B6 FF FF FF C7 06 AC 67 41 00 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 FF 75 08 8B F1 E8 99 FF FF FF C7 06 B8 67 41 00 8B C6 5E 5D C2 04 00 B8 EF 5B 40 00 A3 E8 5A }
    condition:
        all of them
}

rule Windows_Generic_Threat_8d10790b {
    meta:
        author = "Elastic Security"
        id = "8d10790b-6f26-46bf-826e-1371565763f0"
        fingerprint = "7cc33c6684318373e45f5e7440f0a416dd5833a56bc31eb8198a3c36b15dd25e"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "911535923a5451c10239e20e7130d371e8ee37172e0f14fc8cf224d41f7f4c0f"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 81 EC 04 00 00 00 8B 5D 08 8B 1B 83 C3 04 89 5D FC 8B 45 0C 8B 5D FC 89 03 8B E5 5D C2 08 00 55 8B EC 81 EC 0C 00 00 00 C7 45 FC 00 00 00 00 68 00 00 00 00 BB C4 02 00 00 E8 0D 05 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_347f9f54 {
    meta:
        author = "Elastic Security"
        id = "347f9f54-b9a6-4d40-9627-d3cef78f13eb"
        fingerprint = "860f951db43fa3389c5057f7329b5d13d9347b6e04e1363dd0a8060d5a131991"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "45a051651ce1edddd33ecef09bb0fbb978adec9044e64f786b13ed81cabf6a3f"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 10 FF 75 0C 80 65 FC 00 8D 45 F0 C6 45 F0 43 50 C6 45 F1 6F FF 75 08 C6 45 F2 6E C6 45 F3 6E C6 45 F4 65 C6 45 F5 63 C6 45 F6 74 C6 45 F7 47 C6 45 F8 72 C6 45 F9 6F C6 45 FA 75 }
    condition:
        all of them
}

rule Windows_Generic_Threat_20469956 {
    meta:
        author = "Elastic Security"
        id = "20469956-1be6-48e8-b3c4-5706f9630971"
        fingerprint = "67cec754102e3675b4e72ff4826c40614e4856b9cbf12489de3406318990fc85"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "a1f2923f68f5963499a64bfd0affe0a729f5e7bd6bcccfb9bed1d62831a93c47"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 E4 F8 83 EC 5C 53 56 33 C0 C7 44 24 18 6B 00 6C 00 57 8D 4C 24 1C C7 44 24 20 69 00 66 00 C7 44 24 24 2E 00 73 00 C7 44 24 28 79 00 73 00 66 89 44 24 2C C7 44 24 0C 6B 00 6C 00 C7 }
    condition:
        all of them
}

rule Windows_Generic_Threat_742e8a70 {
    meta:
        author = "Elastic Security"
        id = "742e8a70-c150-4903-a551-9123587dd473"
        fingerprint = "733b3563275da0a1b4781b9c0aa07e6e968133ae099eddef9cad3793334b9aa5"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "94f7678be47651aa457256375f3e4d362ae681a9524388c97dc9ed34ba881090"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC E8 96 FF FF FF E8 85 0D 00 00 83 7D 08 00 A3 A4 E9 43 00 74 05 E8 0C 0D 00 00 DB E2 5D C3 8B FF 55 8B EC 83 3D B0 E9 43 00 02 74 05 E8 BA 12 00 00 FF 75 08 E8 07 11 00 00 68 FF 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_79174b5c {
    meta:
        author = "Elastic Security"
        id = "79174b5c-bc1d-40b2-b2e9-f3ddd3ba226c"
        fingerprint = "1e709e5cb8302ea19f9ee93e88f7f910f4271cf1ea2a6c92946fa26f68c63f4d"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c15118230059e85e7a6b65fe1c0ceee8997a3d4e9f1966c8340017a41e0c254c"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 48 56 57 6A 0F 33 C0 59 8D 7D B9 F3 AB 8B 75 0C 6A 38 66 AB 8B 4E 14 AA 8B 46 10 89 4D FC 89 45 F8 59 C1 E8 03 83 E0 3F C6 45 B8 80 3B C1 72 03 6A 78 59 2B C8 8D 45 B8 51 50 56 }
    condition:
        all of them
}

rule Windows_Generic_Threat_232b71a9 {
    meta:
        author = "Elastic Security"
        id = "232b71a9-add2-492d-8b9a-ad2881826ecf"
        fingerprint = "908e2a968e544dfb08a6667f78c92df656c7f2c5cf329dbba6cfdb5ea7b51a57"
        creation_date = "2023-12-20"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1e8b34da2d675af96b34041d4e493e34139fc8779f806dbcf62a6c9c4d9980fe"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 61 61 62 63 64 65 65 66 67 68 69 69 6A 6B 6C 6D 6E 6F 6F 70 71 72 73 74 75 75 76 77 78 79 7A 61 55 }
    condition:
        all of them
}

rule Windows_Generic_Threat_d331d190 {
    meta:
        author = "Elastic Security"
        id = "d331d190-2b66-499e-be08-fed81e5bb5f1"
        fingerprint = "504c204dd82689bacf3875b9fd56a6a865426f3dc76de1d6d6e40c275b069d66"
        creation_date = "2023-12-20"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "6d869d320d977f83aa3f0e7719967c7e54c1bdae9ae3729668d755ee3397a96f"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 83 FA 03 74 04 85 D2 75 05 E8 EE 08 00 00 B8 01 00 00 00 48 83 C4 28 C3 CC CC CC CC 56 57 48 83 EC 38 48 89 CE 8B 01 FF C8 83 F8 05 77 12 48 98 48 8D 0D D1 49 00 00 48 63 3C 81 48 }
    condition:
        all of them
}

rule Windows_Generic_Threat_24191082 {
    meta:
        author = "Elastic Security"
        id = "24191082-58a7-4d1e-88d2-b4935ba5a868"
        fingerprint = "6bf991b391b79e897fe7964499e7e86b7b8fe4f40cf17abba85cb861e840e082"
        creation_date = "2023-12-20"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "4d20878c16d2b401e76d8e7c288cf8ef5aa3c8d4865f440ee6b44d9f3d0cbf33"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 8B 45 0C 48 F7 D0 23 45 08 5D C3 55 8B EC 51 8B 45 0C 48 23 45 08 74 15 FF 75 0C FF 75 08 E8 DA FF FF FF 59 59 03 45 0C 89 45 FC EB 06 8B 45 08 89 45 FC 8B 45 FC 8B E5 5D C3 55 8B EC }
    condition:
        all of them
}

rule Windows_Generic_Threat_efdb9e81 {
    meta:
        author = "Elastic Security"
        id = "efdb9e81-9004-426e-b599-331560b7f0ff"
        fingerprint = "ce1499c8adaad552c127ae80dad90a39eb15e1e461afe3266e8cd6961d3fde79"
        creation_date = "2024-01-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1c3302b14324c9f4e07829f41cd767ec654db18ff330933c6544c46bd19e89dd"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 4D 61 78 69 6D 75 6D 43 68 65 63 6B 42 6F 78 53 69 7A 65 }
        $a2 = { 56 69 73 75 61 6C 50 6C 75 73 2E 4E 61 74 69 76 65 }
    condition:
        all of them
}

rule Windows_Generic_Threat_34622a35 {
    meta:
        author = "Elastic Security"
        id = "34622a35-9ddf-4091-8b0c-c9430ecea57c"
        fingerprint = "427762237cd1040bad58e9d9f7ad36c09134d899c5105e977f94933827c5d5e0"
        creation_date = "2024-01-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c021c6adca0ddf38563a13066a652e4d97726175983854674b8dae2f6e59c83f"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 81 EC 88 00 00 00 C7 45 FC 00 00 00 00 C7 45 F8 00 00 00 00 68 4C 00 00 00 E8 A3 42 00 00 83 C4 04 89 45 F4 8B D8 8B F8 33 C0 B9 13 00 00 00 F3 AB 83 C3 38 53 68 10 00 00 00 E8 82 42 }
    condition:
        all of them
}

rule Windows_Generic_Threat_0ff403df {
    meta:
        author = "Elastic Security"
        id = "0ff403df-cf94-43f3-b8b0-b94068f333f1"
        fingerprint = "3e16fe70b069579a146682d2bbeeeead63c432166b269a6d3464463ccd2bd2f8"
        creation_date = "2024-01-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b3119dc4cea05bef51d1f373b87d69bcff514f6575d4c92da4b1c557f8d8db8f"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 81 EC 00 02 00 00 56 8B F1 57 C6 85 00 FF 63 C7 06 0C 22 41 00 0C 66 69 B6 66 01 7C 06 02 77 03 96 66 69 B6 7B 14 04 F2 05 6B 06 69 96 66 69 6F 07 C5 08 30 66 69 96 66 09 01 0A 67 0B }
    condition:
        all of them
}

rule Windows_Generic_Threat_b1f6f662 {
    meta:
        author = "Elastic Security"
        id = "b1f6f662-ea77-4049-a58a-ed8a97d7738e"
        fingerprint = "f2cd22e34b4694f707ee9042805f5498ce66d35743950096271aaa170f44a2ee"
        creation_date = "2024-01-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1b7eaef3cf1bb8021a00df092c829932cccac333990db1c5dac6558a5d906400"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 67 65 74 5F 4D 53 56 61 6C 75 65 31 30 }
        $a2 = { 73 65 74 5F 4D 53 56 61 6C 75 65 31 30 }
        $a3 = { 67 65 74 5F 4D 53 56 61 6C 75 65 31 31 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2c80562d {
    meta:
        author = "Elastic Security"
        id = "2c80562d-2377-43b2-864f-0f122530b85d"
        fingerprint = "30965c0d6ac30cfb10674b2600e5a1e7b14380072738dd7993bd3eb57c825f24"
        creation_date = "2024-01-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ee8decf1e8e5a927e3a6c10e88093bb4b7708c3fd542d98d43f1a882c6b0198e"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 50 6F 6C 79 6D 6F 64 58 54 2E 65 78 65 }
        $a2 = { 50 6F 6C 79 6D 6F 64 58 54 20 76 31 2E 33 }
        $a3 = { 50 6F 6C 79 6D 6F 64 20 49 6E 63 2E }
    condition:
        all of them
}

rule Windows_Generic_Threat_e96f9e97 {
    meta:
        author = "Elastic Security"
        id = "e96f9e97-cb44-42e5-a06b-98775cbb1f2f"
        fingerprint = "2277fb0b58f923d394f5d4049b6049e66f99aff4ac874849bdc1877b9c6a0d3e"
        creation_date = "2024-01-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "bfbab69e9fc517bc46ae88afd0603a498a4c77409e83466d05db2797234ea7fc"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 7A 47 4D 5E 5A 4D 5D 4B 7D 6D 4A 41 57 4B 54 49 5F 4C 67 6D 54 52 5B 51 46 43 6F 71 40 46 45 53 67 7C 5D 6F }
    condition:
        all of them
}

rule Windows_Generic_Threat_005fd471 {
    meta:
        author = "Elastic Security"
        id = "005fd471-d968-4ece-a61d-91beac4c1e34"
        fingerprint = "30afbb04c257c20ccd2cff15f893715187b7e7b66a9c9f09d076d21466e25a57"
        creation_date = "2024-01-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "502814ed565a923da15626d46fde8cc7fd422790e32b3cad973ed8ec8602b228"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 5F 3F 44 4B 4B 66 25 37 2A 5E 70 42 70 }
        $a2 = { 71 5A 3E 7D 6F 5D 6E 2D 74 48 5E 55 55 22 3C }
        $a3 = { 3E 2D 21 47 45 6A 3C 33 23 47 5B 51 }
    condition:
        all of them
}

rule Windows_Generic_Threat_54b0ec47 {
    meta:
        author = "Elastic Security"
        id = "54b0ec47-79f3-4187-8253-805e7ad102ce"
        fingerprint = "2c3890010aad3c2b54cba08a62b5af6a678849a6b823627bf9e26c8693a89c60"
        creation_date = "2024-01-03"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9c14203069ff6003e7f408bed71e75394de7a6c1451266c59c5639360bf5718c"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 2D 2D 2D 2D 3D 5F 25 73 5F 25 2E 33 75 5F 25 2E 34 75 5F 25 2E 38 58 2E 25 2E 38 58 }
        $a2 = { 25 73 2C 20 25 75 20 25 73 20 25 75 20 25 2E 32 75 3A 25 2E 32 75 3A 25 2E 32 75 20 25 63 25 2E 32 75 25 2E 32 75 }
    condition:
        all of them
}

rule Windows_Generic_Threat_acf6222b {
    meta:
        author = "Elastic Security"
        id = "acf6222b-5859-4b18-a770-04f8fc7f48fd"
        fingerprint = "1046de07f9594a6352a33d892da1b4dc227fdf52a8caf38e8f1532076232c7fc"
        creation_date = "2024-01-03"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ce0def96be08193ab96817ce1279e8406746a76cfcf4bf44e394920d7acbcaa6"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 7D 10 00 75 04 33 C0 5D C3 8B 4D 08 8B 55 0C FF 4D 10 74 0E 8A 01 84 C0 74 08 3A 02 75 04 41 42 EB ED 0F B6 01 0F B6 0A 2B C1 5D C3 55 8B EC 83 EC 24 56 57 8B 7D 08 33 F6 89 75 F8 }
    condition:
        all of them
}

rule Windows_Generic_Threat_5e718a0c {
    meta:
        author = "Elastic Security"
        id = "5e718a0c-3c46-46f7-adfd-b0c3c75b865f"
        fingerprint = "b6f9b85f4438c3097b430495dee6ceef1a88bd5cece823656d9dd325e8d9d4a1"
        creation_date = "2024-01-03"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "430b9369b779208bd3976bd2adc3e63d3f71e5edfea30490e6e93040c1b3bac6"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 44 3A 28 41 3B 3B 30 78 30 30 31 46 30 30 30 33 3B 3B 3B 42 41 29 28 41 3B 3B 30 78 30 30 31 30 30 30 30 33 3B 3B 3B 41 55 29 }
    condition:
        all of them
}

rule Windows_Generic_Threat_fac6d993 {
    meta:
        author = "Elastic Security"
        id = "fac6d993-a9c5-4218-829d-d0f3a3b9a5a0"
        fingerprint = "7502d32cf94496b73e476c7521b84a40426676b335a86bdf1bce7146934efcee"
        creation_date = "2024-01-03"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "f3e7c88e72cf0c1f4cbee588972fc1434065f7cc9bd95d52379bade1b8520278"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 E4 F8 81 EC 4C 04 00 00 53 8B D9 8B 4D 2C 33 C0 89 01 8B 4D 30 56 0F B6 B3 85 00 00 00 89 01 8B 4D 34 57 0F B6 BB 84 00 00 00 89 01 8B 4D 38 89 54 24 10 89 01 8D 44 24 48 50 FF 15 }
    condition:
        all of them
}

rule Windows_Generic_Threat_e7eaa4ca {
    meta:
        author = "Elastic Security"
        id = "e7eaa4ca-45ee-42ea-9604-d9d569eed0aa"
        fingerprint = "ede23e801a67bc43178eea87a83eb0ef32a74d48476a8273a25a7732af6f22a6"
        creation_date = "2024-01-04"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { C8 F7 C6 A8 13 F7 01 E9 2C 99 08 00 4C 03 D1 E9 }
    condition:
        all of them
}

rule Windows_Generic_Threat_97703189 {
    meta:
        author = "Elastic Security"
        id = "97703189-bcac-4b6c-b0d4-9167f5e8085d"
        fingerprint = "9126c3aeaa4ed136424c20aa8e7a487131adc1ae22eb8ab4f514b4687855816f"
        creation_date = "2024-01-04"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "968ba3112c54f3437b9abb6137f633d919d75137d790af074df40a346891cfb5"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 5D E9 2A 1C 00 00 8B FF 55 8B EC 8B 45 08 56 8B F1 C6 46 0C 00 85 C0 75 63 E8 6F 29 00 00 89 46 08 8B 48 6C 89 0E 8B 48 68 89 4E 04 8B 0E 3B 0D 98 06 49 00 74 12 8B 0D B4 05 49 00 85 }
    condition:
        all of them
}

rule Windows_Generic_Threat_ca0686e1 {
    meta:
        author = "Elastic Security"
        id = "ca0686e1-001f-44d2-ae2f-51c473769723"
        fingerprint = "4663eefedb6f3f502adfb4f64278d1c535ba3a719d007a280e9943914121cd81"
        creation_date = "2024-01-05"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "15c7ce1bc55549efc86dea74a90f42fb4665fe15b14f760037897c772159a5b5"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 53 8B 5D 08 56 57 8B F9 8B 77 10 8B C6 2B C3 89 75 FC 3B 45 0C 72 03 8B 45 0C 83 7F 14 10 72 02 8B 0F 8D 14 19 2B F0 8B CE 03 C2 2B CB 41 51 50 52 E8 62 1A 00 00 83 C4 0C 8B CF 56 }
    condition:
        all of them
}

rule Windows_Generic_Threat_97c1a260 {
    meta:
        author = "Elastic Security"
        id = "97c1a260-9b43-458e-a9ac-2391aee1bcb8"
        fingerprint = "9cd93a8def2d2fac61a5b37d82b97c18ce8bf3410aa6ec7531ec28378f5c98cc"
        creation_date = "2024-01-07"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2cc85ebb1ef07948b1ddf1a793809b76ee61d78c07b8bf6e702c9b17346a20f1"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 53 56 57 E8 14 31 00 00 8B F0 85 F6 0F 84 39 01 00 00 8B 16 33 DB 8B CA 8D 82 90 00 00 00 3B D0 74 0E 8B 7D 08 39 39 74 09 83 C1 0C 3B C8 75 F5 8B CB 85 C9 0F 84 11 01 00 00 8B 79 }
    condition:
        all of them
}

rule Windows_Generic_Threat_a440f624 {
    meta:
        author = "Elastic Security"
        id = "a440f624-c7ec-4f26-bfb5-982bae5f6887"
        fingerprint = "0f538f8f4eb2e71fb74d8305a179fc2ad880ab5a4cfd37bd35b5da2629ed892c"
        creation_date = "2024-01-07"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "3564fec3d47dfafc7e9c662654865aed74aedeac7371af8a77e573ea92cbd072"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 2E 20 49 50 20 3D 20 25 73 2C 20 50 6F 72 74 20 3D 20 25 64 2C 20 73 6B 20 3D 20 25 64 }
        $a2 = { 2E 20 49 50 20 3D 20 25 73 2C 20 50 6F 72 74 20 3D 20 25 64 2C 20 4C 65 6E 20 3D 20 25 64 }
    condition:
        all of them
}

rule Windows_Generic_Threat_b577c086 {
    meta:
        author = "Elastic Security"
        id = "b577c086-37bd-4227-8cde-f15e2ce0d0ae"
        fingerprint = "0de3cab973de067f2c10252bf761ced353de57c03c4b2e95db05ee3ca30259ea"
        creation_date = "2024-01-07"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "27dd61d4d9997738e63e813f8b8ea9d5cf1291eb02d20d1a2ad75ac8aa99459c"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 24 83 7D 08 00 75 0A B8 9A FF FF FF E9 65 02 00 00 8B 45 08 89 45 FC 8B 4D FC 83 79 18 00 75 0A B8 9A FF FF FF E9 4C 02 00 00 8B 55 FC 83 7A 7C 00 74 0C 8B 45 08 50 E8 5F 06 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_62e1f5fc {
    meta:
        author = "Elastic Security"
        id = "62e1f5fc-325b-46e0-8c03-1a73e873ab16"
        fingerprint = "64839df90109a0c706c0a3626ba6c4c2eaa5dcd564f0e9889ab9ad4f12e150fe"
        creation_date = "2024-01-07"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "4a692e244a389af0339de8c2d429b541d6d763afb0a2b1bb20bee879330f2f42"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 43 6C 69 65 6E 74 2E 48 61 6E 64 6C 65 5F 50 61 63 6B 65 74 }
        $a2 = { 67 65 74 5F 73 45 78 70 59 65 61 72 }
        $a3 = { 73 65 74 5F 73 45 78 70 59 65 61 72 }
    condition:
        all of them
}

rule Windows_Generic_Threat_55d6a1ab {
    meta:
        author = "Elastic Security"
        id = "55d6a1ab-2041-44a5-ae0e-23671fa2b001"
        fingerprint = "cd81b61929b18d59630814718443c4b158f9dcc89c7d03a46a531ffc5843f585"
        creation_date = "2024-01-07"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1ca6ed610479b5aaaf193a2afed8f2ca1e32c0c5550a195d88f689caab60c6fb"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 51 51 31 33 37 32 33 39 32 34 38 20 }
        $a2 = { 74 65 6E 63 65 6E 74 3A 2F 2F 6D 65 73 73 61 67 65 2F 3F 75 69 6E 3D 31 33 37 32 33 39 32 34 38 26 53 69 74 65 3D 63 66 }
    condition:
        all of them
}

rule Windows_Generic_Threat_f7d3cdfd {
    meta:
        author = "Elastic Security"
        id = "f7d3cdfd-72eb-4298-b3ff-432f5c4347c9"
        fingerprint = "db703a2ddcec989a81b99a67e61f4be34a2b0e55285c2bdec91cd2f7fc7e52f3"
        creation_date = "2024-01-07"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "f9df83d0b0e06884cdb4a02cd2091ee1fadeabb2ea16ca34cbfef4129ede251f"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 51 56 57 E8 A3 D0 FF FF 83 78 68 00 74 21 FF 75 24 FF 75 20 FF 75 18 FF 75 14 FF 75 10 FF 75 0C FF 75 08 E8 E5 8C FF FF 83 C4 1C 85 C0 75 73 8B 7D 1C 8D 45 F8 50 8D 45 FC 50 57 FF }
    condition:
        all of them
}

rule Windows_Generic_Threat_0350ed31 {
    meta:
        author = "Elastic Security"
        id = "0350ed31-ed07-4e9a-8488-3765c990f25c"
        fingerprint = "aac41abf60a16c02c6250c0468c6f707f9771b48da9e78633de7141d09ca23c8"
        creation_date = "2024-01-07"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "008f9352765d1b3360726363e3e179b527a566bc59acecea06bd16eb16b66c5d"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 35 6A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 3F }
    condition:
        all of them
}

rule Windows_Generic_Threat_13236f14 {
    meta:
        author = "Elastic Security"
        id = "13236f14-3557-4ad9-aa19-78e79b2efd4e"
        fingerprint = "8b05f1cd70c604619f0f45467da05efa7a01a9dd49cd4e3e7fc22de814489932"
        creation_date = "2024-01-08"
        last_modified = "2025-05-27"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "a46bbcce396495c513190b272d3bc43d6579a201f5e8d103628c62888a82fa8b"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 83 EC 20 48 89 CB 48 89 D6 48 89 D8 48 63 40 3C 48 8D 04 03 8B 80 88 00 00 00 4C 8D 34 18 4D 33 ED 48 33 FF 41 8B 46 20 48 8D 04 18 41 8B CD 03 C9 03 C9 8B C9 8B 04 08 48 8D 04 18 48 89 C1 }
        $b1 = "Trojan.Fabookie.Gen."
    condition:
        $a1 and not $b1
}

rule Windows_Generic_Threat_a1cef0cd {
    meta:
        author = "Elastic Security"
        id = "a1cef0cd-a811-4d7b-b24e-7935c0418c7a"
        fingerprint = "9285f0ea8ed0ceded2f3876ef197b67e8087f7de82a72e0cd9899b05015eee79"
        creation_date = "2024-01-08"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "71f519c6bd598e17e1298d247a4ad37b78685ca6fd423d560d397d34d16b7db8"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 53 8B DA 89 45 FC 8B 45 FC E8 76 00 00 00 33 C0 55 68 F0 A0 41 00 64 FF 30 64 89 20 8B 45 FC 80 78 20 01 74 10 8B 45 FC 8B 40 04 8B D3 E8 CE FC FF FF 40 75 0F 8B 45 FC 8B 40 04 8B }
    condition:
        all of them
}

rule Windows_Generic_Threat_e5f4703f {
    meta:
        author = "Elastic Security"
        id = "e5f4703f-e834-4904-9036-a8c5996058c8"
        fingerprint = "3072ea028b0716e88820782a2658d1f424d57bd988ccfcc1581991649cf52b19"
        creation_date = "2024-01-09"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "362bda1fad3fefce7d173617909d3c1a0a8e234e22caf3215ee7c6cef6b2743b"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 E4 F8 83 EC 08 83 79 14 08 56 57 8B F1 72 02 8B 31 8B 41 10 8B CE 8D 3C 46 8B D7 E8 AC FA FF FF 8B 75 08 2B F8 D1 FF 0F 57 C0 57 50 0F 11 06 8B CE C7 46 10 00 00 00 00 C7 46 14 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_8b790aba {
    meta:
        author = "Elastic Security"
        id = "8b790aba-02b4-4c71-a51e-3a56ea5728ec"
        fingerprint = "8581397f15b9985bafa5248f0e7f044bf80c82e441d2216dc0976c806f658d2e"
        creation_date = "2024-01-09"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ec98bfff01d384bdff6bbbc5e17620b31fa57c662516157fd476ef587b8d239e"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 7A 66 62 50 4A 64 73 72 78 77 7B 7B 79 55 36 46 42 50 4A 3F 20 2E 6E 3E 36 65 73 7A }
        $a2 = { 50 36 7B 77 64 71 79 64 46 4A 73 64 79 62 45 7A 77 63 62 64 }
    condition:
        all of them
}

rule Windows_Generic_Threat_76a7579f {
    meta:
        author = "Elastic Security"
        id = "76a7579f-4a9b-4dae-935c-14d829d3c416"
        fingerprint = "ba5bfc0e012a22172f138c498560a606e6754efa0fa145799f00725e130ad90f"
        creation_date = "2024-01-09"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "76c73934bcff7e4ee08b068d1e02b8f5c22161262d127de2b4ac2e81d09d84f6"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 8B 55 10 8B 45 08 8B C8 85 D2 74 09 C6 01 00 41 83 EA 01 75 F7 5D C3 55 8B EC 64 A1 30 00 00 00 83 EC 18 8B 40 0C 53 56 57 8B 78 0C E9 A7 00 00 00 8B 47 30 33 F6 8B 5F 2C 8B 3F 89 45 }
    condition:
        all of them
}

rule Windows_Generic_Threat_3f060b9c {
    meta:
        author = "Elastic Security"
        id = "3f060b9c-8c35-4f0f-9dfd-10be6355bea9"
        fingerprint = "5bc1d19faa8fc07ef669f6f63baceee5fe452c0e2d54d6154bcc01e11606ae6f"
        creation_date = "2024-01-10"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "32e7a40b13ddbf9fc73bd12c234336b1ae11e2f39476de99ebacd7bbfd22fba0"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 51 53 56 8B F1 E8 4B BE FF FF 8D 45 FC 8B CE 50 FF 75 10 FF 75 0C E8 69 FE FF FF 8B D8 8B CE 53 E8 4B FD FF FF 85 C0 0F 84 C6 00 00 00 8B 46 40 83 F8 02 0F 84 B3 00 00 00 83 F8 05 }
    condition:
        all of them
}

rule Windows_Generic_Threat_dbae6542 {
    meta:
        author = "Elastic Security"
        id = "dbae6542-b343-4320-884c-c0ce97a431f1"
        fingerprint = "880aafd423494eccab31342bdfec392fdf4a7b4d98614a0c3b5302d62bcf5ba8"
        creation_date = "2024-01-10"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c73f533f96ed894b9ff717da195083a594673e218ee9a269e360353b9c9a0283"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 20 B8 0B 00 00 20 10 27 00 00 6F 29 00 00 0A 28 1F 00 00 0A 7E 0F 00 00 04 2D 0A 28 27 00 00 06 28 19 00 00 06 7E 15 00 00 04 6F 2A 00 00 0A 26 17 2D C8 2A EE 16 80 0F 00 00 04 14 }
    condition:
        all of them
}

rule Windows_Generic_Threat_808f680e {
    meta:
        author = "Elastic Security"
        id = "808f680e-db35-488f-b942-79213890b336"
        fingerprint = "4b4b3b244d0168b11a8df4805f9043c6e4039ced332a7ba9c9d0d962ad6f6a0e"
        creation_date = "2024-01-10"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "df6955522532e365239b94e9d834ff5eeeb354eec3e3672c48be88725849ac1c"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 20 00 00 00 00 FE 01 2A 13 30 02 00 6C 00 00 00 01 00 00 11 20 00 00 00 00 FE 0E 00 00 38 54 00 00 00 00 FE 0C 00 00 20 01 00 00 00 FE 01 39 12 00 00 00 FE 09 01 00 FE 09 02 00 51 }
    condition:
        all of them
}

rule Windows_Generic_Threat_073909cf {
    meta:
        author = "Elastic Security"
        id = "073909cf-7e0d-48fa-a631-e1b641040570"
        fingerprint = "717da3b409c002ff6c6428690faf6e6018daedfaf9ec95b6fb9884cacc27dc20"
        creation_date = "2024-01-10"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "89a6dc518c119b39252889632bd18d9dfdae687f7621310fb14b684d2f85dad8"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 C4 F0 53 56 89 55 FC 8B F0 8B 45 FC E8 CF E5 FF FF 33 C0 55 68 F2 39 40 00 64 FF 30 64 89 20 33 DB 68 04 3A 40 00 68 0C 3A 40 00 E8 70 FC FF FF 50 E8 82 FC FF FF 89 45 F8 68 18 3A }
    condition:
        all of them
}

rule Windows_Generic_Threat_820fe9c9 {
    meta:
        author = "Elastic Security"
        id = "820fe9c9-2abc-4dd5-84e2-a74fbded4dc6"
        fingerprint = "e43f4fee9e23233bf8597decac79bda4790b5682f5e0fe86e3a13cb18724ea3e"
        creation_date = "2024-01-11"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1102a499b8a863bdbfd978a1d17270990e6b7fe60ce54b9dd17492234aad2f8c"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 2E 2A 73 74 72 75 63 74 20 7B 20 46 20 75 69 6E 74 70 74 72 3B 20 58 30 20 63 68 61 6E 20 73 74 72 69 6E 67 3B 20 58 31 20 62 6F 6F 6C 20 7D }
    condition:
        all of them
}

rule Windows_Generic_Threat_89efd1b4 {
    meta:
        author = "Elastic Security"
        id = "89efd1b4-9a4b-4749-8b34-630883d2d45b"
        fingerprint = "659bdc9af01212de3d2492e0805e801b0a00630bd699360be15d3fe5b221f6b3"
        creation_date = "2024-01-11"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "937c8bc3c89bb9c05b2cb859c4bf0f47020917a309bbadca36236434c8cdc8b9"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 81 EC E0 01 00 00 48 89 9C 24 F8 01 00 00 48 83 F9 42 0F 85 03 01 00 00 48 89 84 24 F0 01 00 00 48 89 9C 24 F8 01 00 00 44 0F 11 BC 24 88 01 00 00 44 0F 11 BC 24 90 01 00 00 44 0F 11 BC 24 }
    condition:
        all of them
}

rule Windows_Generic_Threat_61315534 {
    meta:
        author = "Elastic Security"
        id = "61315534-9d80-428b-bc56-ff4836ab0c4a"
        fingerprint = "e5cff64bc04b271237015154ddeb275453536ffa8cbce60389b6ed37e6478788"
        creation_date = "2024-01-11"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "819447ca71080f083b1061ed6e333bd9ef816abd5b0dd0b5e6a58511ab1ce8b9"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 51 8A 4D 08 F6 C1 01 74 0A DB 2D B0 D7 41 00 DB 5D 08 9B F6 C1 08 74 10 9B DF E0 DB 2D B0 D7 41 00 DD 5D F8 9B 9B DF E0 F6 C1 10 74 0A DB 2D BC D7 41 00 DD 5D F8 9B F6 C1 04 74 09 }
    condition:
        all of them
}

rule Windows_Generic_Threat_eab96cf2 {
    meta:
        author = "Elastic Security"
        id = "eab96cf2-f25a-4149-9328-3f7af50b2ad8"
        fingerprint = "a07bbc803aa7ae54d0c0b2b15edf8378646f06906151998ac3d5491245813dd9"
        creation_date = "2024-01-11"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2be8a2c524f1fb2acb2af92bc56eb9377c4e16923a06f5ac2373811041ea7982"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 20 41 52 FF E0 58 41 59 5A 48 8B 12 E9 4B FF FF FF 5D 48 31 DB 53 49 BE 77 69 6E 68 74 74 70 00 41 56 48 89 E1 49 C7 C2 4C 77 26 07 FF D5 53 53 48 89 E1 53 5A 4D 31 C0 4D 31 C9 53 53 }
    condition:
        all of them
}

rule Windows_Generic_Threat_11a56097 {
    meta:
        author = "Elastic Security"
        id = "11a56097-c019-43dc-b401-c3bd5e88ce17"
        fingerprint = "37fda03cc0d50dc8bf6adfb83369649047e73fe33929f6579bf806b343eb092c"
        creation_date = "2024-01-12"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "98d538c8f074d831b7a91e549e78f6549db5d2c53a10dbe82209d15d1c2e9b56"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 6E 6F 69 74 70 65 63 78 45 74 61 6D 72 6F 46 65 67 61 6D 49 64 61 42 }
        $a2 = { 65 74 75 62 69 72 74 74 41 65 74 65 6C 6F 73 62 4F }
    condition:
        all of them
}

rule Windows_Generic_Threat_f3bef434 {
    meta:
        author = "Elastic Security"
        id = "f3bef434-0688-4672-a02f-40615cc429b1"
        fingerprint = "a05dfdf2f8f15335acb2772074ad42f306a4b33ab6a19bdac99a0215820a6f7b"
        creation_date = "2024-01-12"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "98d538c8f074d831b7a91e549e78f6549db5d2c53a10dbe82209d15d1c2e9b56"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 6F 70 00 06 EB 72 06 26 0A 00 01 45 6F 04 00 00 8F 7B 02 06 26 0A 00 01 44 6F 70 00 06 D5 72 00 00 00 B8 38 1D 2C EB 2C 1A 00 00 00 B8 38 14 04 00 00 8F 7B 00 00 00 BD 38 32 2C 00 00 00 BE 38 }
    condition:
        all of them
}

rule Windows_Generic_Threat_c6f131c5 {
    meta:
        author = "Elastic Security"
        id = "c6f131c5-8737-4f48-a0fe-a94e9565481e"
        fingerprint = "c4349bd78cdc64430d15caf7efd663ff88d79d69ecf9f8118122b9a85543057d"
        creation_date = "2024-01-12"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "247314baaaa993b8db9de7ef0e2998030f13b99d6fd0e17ffd59e31a8d17747a"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 20 48 8B 59 08 8B 13 44 8B 43 04 48 83 C3 08 89 D0 44 09 C0 74 07 E8 B6 FF FF FF EB E8 48 83 C4 20 5B C3 53 45 31 DB BB 0D 00 00 00 48 8B 41 10 45 89 DA 49 C1 E2 04 4A 83 3C 10 00 74 }
    condition:
        all of them
}

rule Windows_Generic_Threat_b2a054f8 {
    meta:
        author = "Elastic Security"
        id = "b2a054f8-160f-4932-b5fe-c7d78a1f9b74"
        fingerprint = "09f1724963bfdde810b61d80049def388c89f6a21195e90a869bb22d19d074de"
        creation_date = "2024-01-12"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "63d2478a5db820731a48a7ad5a20d7a4deca35c6b865a17de86248bef7a64da7"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 7E 38 7E 40 7E 44 48 4C 2A 7E 7E 58 5D 5C }
        $a2 = { 39 7B 34 74 26 39 3A 62 3A 66 25 6A }
        $a3 = { 5B 50 44 7E 66 7E 71 7E 77 7E 7C 7E }
    condition:
        all of them
}

rule Windows_Generic_Threat_fcab7e76 {
    meta:
        author = "Elastic Security"
        id = "fcab7e76-5edd-4485-9983-bcc5e9cb0a08"
        fingerprint = "8a01a3a398cfaa00c1b194b2abc5a0c79d21010abf27dffe5eb8fdc602db7ad1"
        creation_date = "2024-01-12"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "67d7e016e401bd5d435eecaa9e8ead341aed2f373a1179069f53b64bda3f1f56"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 FA 00 2B CD 65 50 7C FF CF 34 00 80 41 BF 1E 12 1A F9 20 0F 56 EE 9F BA C0 22 7E 97 FC CB 03 C7 67 9A AE 8A 60 C0 B3 6C 0D 00 2B 2C 78 83 B5 88 03 17 3A 51 4A 1F 30 D2 C0 53 DC 09 7A BF 2D }
    condition:
        all of them
}

rule Windows_Generic_Threat_90e4f085 {
    meta:
        author = "Elastic Security"
        id = "90e4f085-2f53-4e5e-bcb6-c24823539241"
        fingerprint = "1d40eef44166b3cc89b1f2ba9c667032fa44cba271db8b82cc2fed738225712a"
        creation_date = "2024-01-12"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1a6a290d98f5957d00756fc55187c78030de7031544a981fd2bb4cfeae732168"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 39 39 21 3A 37 3B 45 3C 50 3D 5B 3E 66 3F }
        $a2 = { 66 32 33 39 20 3A 4E 3D 72 68 74 76 48 }
        $a3 = { 32 78 37 7A 42 5A 4C 22 2A 66 49 7A 75 }
    condition:
        all of them
}

rule Windows_Generic_Threat_04a9c177 {
    meta:
        author = "Elastic Security"
        id = "04a9c177-cacf-4509-b8dc-f30a628b7699"
        fingerprint = "b36da73631711de0213658d30d3079f45449c303d8eb87b8342d1bd20120c7bb"
        creation_date = "2024-01-12"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0cccdde4dcc8916fb6399c181722eb0da2775d86146ce3cb3fc7f8cf6cd67c29"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 6F 81 00 06 FE 3C A3 C3 D6 37 16 00 C2 87 21 EA 80 33 09 E5 00 2C 0F 24 BD 70 BC CB FB 00 94 5E 1B F8 14 F6 E6 95 07 01 CD 02 B0 D7 30 25 65 99 74 01 D6 A4 47 B3 20 AF 27 D8 11 7F 03 57 F6 37 }
    condition:
        all of them
}

rule Windows_Generic_Threat_45d1e986 {
    meta:
        author = "Elastic Security"
        id = "45d1e986-78fb-4a83-97f6-2b40c657e709"
        fingerprint = "facb67b78cc4d6cf5d141fd7153d331209e5ce46f29c0078c7e5683165c37057"
        creation_date = "2024-01-12"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fd159cf2f9bd48b0f6f5958eef8af8feede2bcbbea035a7e56ce1ff72d3f47eb"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 45 00 06 00 00 00 08 28 45 00 09 00 00 00 14 28 45 00 09 00 00 00 20 28 45 00 07 00 00 00 28 28 45 00 0A 00 00 00 34 28 45 00 0B 00 00 00 40 28 45 00 09 00 00 00 5B 81 45 00 00 00 00 00 4C }
    condition:
        all of them
}

rule Windows_Generic_Threat_83c38e63 {
    meta:
        author = "Elastic Security"
        id = "83c38e63-6a18-4def-abf2-35e36210e4cf"
        fingerprint = "9cc8ee8dfa6080a18575a494e0b424154caecedcc8c8fd07dd3c91956c146d1e"
        creation_date = "2024-01-12"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2121a0e5debcfeedf200d7473030062bc9f5fbd5edfdcd464dfedde272ff1ae7"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 32 65 65 64 36 35 36 64 64 35 38 65 39 35 30 35 62 34 33 39 35 34 32 30 31 39 36 66 62 33 35 36 }
        $a2 = { 34 2A 34 4A 34 52 34 60 34 6F 34 7C 34 }
    condition:
        all of them
}

rule Windows_Generic_Threat_bd24be68 {
    meta:
        author = "Elastic Security"
        id = "bd24be68-3d72-44fd-92f2-39f592d47d0e"
        fingerprint = "35ff6c9b338ef95585d8d0059966857f6e5a426fa5f357acb844d264d239c70d"
        creation_date = "2024-01-12"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fd159cf2f9bd48b0f6f5958eef8af8feede2bcbbea035a7e56ce1ff72d3f47eb"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 8B 4D 0C 56 8B 75 08 89 0E E8 AB 17 00 00 8B 48 24 89 4E 04 E8 A0 17 00 00 89 70 24 8B C6 5E 5D C3 55 8B EC 56 E8 8F 17 00 00 8B 75 08 3B 70 24 75 0E 8B 76 04 E8 7F 17 00 00 89 70 24 }
    condition:
        all of them
}

rule Windows_Generic_Threat_a0c7b402 {
    meta:
        author = "Elastic Security"
        id = "a0c7b402-cee5-4da6-9a32-72b1a0ae0f8d"
        fingerprint = "0ca7d91a97c12f4640dd367d19d8645dd1da713cfa62289c40f8c34202ddf256"
        creation_date = "2024-01-16"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "5814d7712304800d92487b8e1108d20ad7b44f48910b1fb0a99e9b36baa4333a"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 89 E5 57 56 83 E4 F8 83 EC 20 8B 75 10 8B 7D 0C 89 E0 8D 4C 24 18 6A 05 6A 18 50 51 FF 75 08 68 BC 52 4D 90 E8 26 00 00 00 83 C4 18 85 FF 74 06 8B 4C 24 08 89 0F 85 F6 74 08 80 7C 24 15 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_42b3e0d7 {
    meta:
        author = "Elastic Security"
        id = "42b3e0d7-ec42-4940-b5f3-e9782997dccf"
        fingerprint = "7d3974400d05bc7bbcd63c99e8257d0676b38335de74a4bcfde9e86553f50f08"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "99ad416b155970fda383a63fe61de2e4d0254e9c9e09564e17938e8e2b49b5b7"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 C4 F8 53 33 DB 6A 00 8D 45 F8 50 8B 45 0C 50 8B 45 10 50 6A 00 6A 00 33 C9 33 D2 8B 45 08 E8 B1 F7 FF FF 85 C0 75 05 BB 01 00 00 00 8B C3 5B 59 59 5D C2 0C 00 8D 40 00 53 BB E0 E1 }
    condition:
        all of them
}

rule Windows_Generic_Threat_66142106 {
    meta:
        author = "Elastic Security"
        id = "66142106-d602-4b1b-a79b-64d692c613ca"
        fingerprint = "b5816297691fefc46ab11cb175a4e20d40c5095c20417e80590ceb05bd1ec974"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "cd164a65fb2a496ad7b54c782f25fbfca0540d46d2c0d6b098d7be516c4ce021"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 10 6A 00 8D 4D F0 E8 6B FF FF FF 8B 45 F4 BA E9 FD 00 00 39 50 08 74 0C E8 29 48 00 00 33 D2 85 C0 75 01 42 80 7D FC 00 74 0A 8B 4D F0 83 A1 50 03 00 00 FD 8B C2 C9 C3 8B FF 56 }
    condition:
        all of them
}

rule Windows_Generic_Threat_51a1d82b {
    meta:
        author = "Elastic Security"
        id = "51a1d82b-2ae0-45c9-b51d-9b54454dfcee"
        fingerprint = "fddf98cdb00734e50908161d6715e807b1c4437789af524d6f0a17df55572261"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1a7adde856991fa25fac79048461102fba58cda9492d4f5203b817d767a81018"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 04 53 56 57 89 4D FC 8B 45 FC 50 FF 15 D0 63 41 00 5F 5E 5B C9 C3 CC CC CC CC CC 66 8B 01 56 66 8B 32 57 66 3B F0 72 44 75 0A 66 8B 79 02 66 39 7A 02 72 38 66 3B F0 75 14 66 8B }
    condition:
        all of them
}

rule Windows_Generic_Threat_dee3b4bf {
    meta:
        author = "Elastic Security"
        id = "dee3b4bf-f09e-46a7-b177-6b1445db88ad"
        fingerprint = "6f6cf93e5ac640d1e71f9554752a846c3cc051d95c232e2f4d8fa383d5a3b5af"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c7f4b63fa5c7386d6444c0d0428a8fe328446efcef5fda93821f05e86efd2fba"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 4A 75 73 74 20 63 6F 70 79 20 74 68 65 20 70 61 74 63 68 20 74 6F 20 74 68 65 20 70 72 6F 67 72 61 6D 20 64 69 72 65 63 74 6F 72 79 20 61 6E 64 20 61 70 70 6C 79 2E }
    condition:
        all of them
}

rule Windows_Generic_Threat_fdbcd3f2 {
    meta:
        author = "Elastic Security"
        id = "fdbcd3f2-17e6-49d4-997b-91e6a85e4226"
        fingerprint = "2a69deed3fe05b64cb37881ce50cae8972e7a610fd32c4b7f9155409bc5b297c"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9258e4fe077be21ad7ae348868f1ac6226f6e9d404c664025006ab4b64222369"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 C4 FC 60 8B 75 0C 8D A4 24 00 00 00 00 8D A4 24 00 00 00 00 90 56 E8 22 00 00 00 0B C0 75 05 89 45 FC EB 11 89 35 84 42 40 00 46 8B 5D 08 38 18 75 E3 89 45 FC 61 8B 45 FC C9 C2 08 }
    condition:
        all of them
}

rule Windows_Generic_Threat_b7852ccf {
    meta:
        author = "Elastic Security"
        id = "b7852ccf-ba11-44e2-95b9-eb92d6976e15"
        fingerprint = "f33ef7996bcb0422227b9481d85b3663fb0f13f1be01837b42ac0c5f0bcff781"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "5ac70fa959be4ee37c0c56f0dd04061a5fed78fcbde21b8449fc93e44a8c133a"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 45 2B 34 2C 3D 43 4A 32 3A 24 40 2F 22 3E 3F 3C 24 44 }
        $a2 = { 67 6F 72 67 65 6F 75 73 68 6F 72 6E 79 }
        $a3 = { 62 6C 61 63 6B 20 68 61 69 72 75 6E 73 68 61 76 65 64 }
    condition:
        all of them
}

rule Windows_Generic_Threat_c3c8f21a {
    meta:
        author = "Elastic Security"
        id = "c3c8f21a-4722-4b6f-85e1-023d45487aeb"
        fingerprint = "5bae56d41d4582aed0a6fd54eab53ce6d47f0d70711cc17e77f8e85019d2ac7e"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9a102873dd37d08f53dcf6b5dad2555598a954d18fb3090bbf842655c5fded35"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 89 E5 83 EC 14 53 56 57 8D 7D F7 BE 1E CA 40 00 B9 02 00 00 00 F3 A5 A4 68 62 CA 40 00 68 64 CA 40 00 E8 A8 25 00 00 83 C4 08 89 C3 8D 45 EC 50 E8 CA 24 00 00 59 8D 45 EC 50 E8 80 26 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_a3d51e0c {
    meta:
        author = "Elastic Security"
        id = "a3d51e0c-9d49-48e5-abdb-ceeb10780cfa"
        fingerprint = "069a218c752b5aac5b26b19b36b641b3dd31f09d7fcaae735efb52082a3495cc"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "18bd25df1025cd04b0642e507b0170bc1a2afba71b2dc4bd5e83cc487860db0d"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 53 56 8B 75 08 33 DB 39 5D 14 57 75 10 3B F3 75 10 39 5D 0C 75 12 33 C0 5F 5E 5B 5D C3 3B F3 74 07 8B 7D 0C 3B FB 77 1B E8 05 F8 FF FF 6A 16 5E 89 30 53 53 53 53 53 E8 97 F7 FF FF 83 }
    condition:
        all of them
}

rule Windows_Generic_Threat_54ccad4d {
    meta:
        author = "Elastic Security"
        id = "54ccad4d-3b8d-4abb-88eb-d428d661169d"
        fingerprint = "4fe13c4ca3569912978a0c2231ec53a715a314e1158e09bc0c61f18151cfffa3"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fe4aad002722d2173dd661b7b34cdb0e3d4d8cd600e4165975c48bf1b135763f"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 4D 55 73 65 72 4E 61 74 69 66 65 72 63 }
        $a2 = { 4D 79 52 65 67 53 61 76 65 52 65 63 6F 72 64 }
        $a3 = { 53 74 65 61 6C 65 72 54 69 6D 65 4F 75 74 }
    condition:
        all of them
}

rule Windows_Generic_Threat_6ee18020 {
    meta:
        author = "Elastic Security"
        id = "6ee18020-71e2-4003-99ef-963663e94740"
        fingerprint = "b8b18dcec6556bc7fb9b9f257a6485bcd6dfde96fc5c7e8145664de55d0c6803"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "d58d8f5a7efcb02adac92362d8c608e6d056824641283497b2e1c1f0e2d19b0a"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 53 8B 5D 0C 8B 45 08 50 E8 9C 19 02 00 59 89 03 89 53 04 83 7B 04 00 75 07 83 3B 00 76 10 EB 02 7E 0C C6 43 28 01 33 C0 5B 5D C3 5B 5D C3 B8 01 00 00 00 5B 5D C3 90 90 90 55 8B EC 53 }
    condition:
        all of them
}

rule Windows_Generic_Threat_8eb547db {
    meta:
        author = "Elastic Security"
        id = "8eb547db-81e4-4c64-9bab-b7944af32345"
        fingerprint = "2de0d43a4c1c4b3ecef7272d3f224bd5203c130365ff49a02a9200b3f53fe6ba"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "3fc821b63dfa653b86b11201073997fa4dc273124d050c2a7c267ac789d8a447"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 20 B8 0B 00 00 20 10 27 00 00 6F 29 00 00 0A 28 1F 00 00 0A 7E 0D 00 00 04 2D 0A 28 23 00 00 06 28 19 00 00 06 7E 14 00 00 04 6F 2A 00 00 0A 26 17 2D C8 2A 13 30 01 00 41 00 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_803feff4 {
    meta:
        author = "Elastic Security"
        id = "803feff4-e4c2-4d8c-b736-47bb10fd5ce8"
        fingerprint = "3bbb00aa18086ac804f6ddf99a50821744a420f46b6361841b8bcd2872e597f1"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "8f150dfb13e4a2ff36231f873e4c0677b5db4aa235d8f0aeb41e02f7e31c1e05"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 6F 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 8D 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 92 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 9A 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 }
    condition:
        all of them
}

rule Windows_Generic_Threat_9c7d2333 {
    meta:
        author = "Elastic Security"
        id = "9c7d2333-f2c4-4d90-95ce-d817da5cb2a3"
        fingerprint = "3f003cc34b797887b5bbfeb729441d7fdb537d4516f13b215e1f6eceb5a8afaf"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "85219f1402c88ab1e69aa99fe4bed75b2ad1918f4e95c448cdc6a4b9d2f9a5d4"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 81 EC 64 09 00 00 57 C6 85 00 F8 FF FF 00 B9 FF 00 00 00 33 C0 8D BD 01 F8 FF FF F3 AB 66 AB AA C6 85 00 FC FF FF 00 B9 FF 00 00 00 33 C0 8D BD 01 FC FF FF F3 AB 66 AB AA C7 85 AC F6 }
    condition:
        all of them
}

rule Windows_Generic_Threat_747b58af {
    meta:
        author = "Elastic Security"
        id = "747b58af-6edb-42f2-8a1b-e462399ef61e"
        fingerprint = "79faab4fda6609b2c95d24de92a3a417d2f5e58f3f83c856fa9f32e80bed6f37"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ee28e93412c59d63155fd79bc99979a5664c48dcb3c77e121d17fa985fcb0ebe"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 5C 43 3D 5D 78 48 73 66 40 22 33 2D 34 }
        $a2 = { 79 5A 4E 51 61 4A 21 43 43 56 31 37 74 6B }
        $a3 = { 66 72 7A 64 48 49 2D 4E 3A 4D 23 43 }
    condition:
        all of them
}

rule Windows_Generic_Threat_c3c4e847 {
    meta:
        author = "Elastic Security"
        id = "c3c4e847-ef6f-430d-9778-d48326fb4eb0"
        fingerprint = "017a8ec014fed493018cff128b973bb648dbb9a0d1bede313d237651d3f6531a"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "86b37f0b2d9d7a810b5739776b4104f1ded3a1228c4ec2d104d26d8eb26aa7ba"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 2E 3F 41 56 3F 24 5F 52 65 66 5F 63 6F 75 6E 74 40 55 41 70 69 44 61 74 61 40 40 40 73 74 64 40 40 }
    condition:
        all of them
}

rule Windows_Generic_Threat_6542ebda {
    meta:
        author = "Elastic Security"
        id = "6542ebda-c91e-449e-88c4-244fba69a4b2"
        fingerprint = "a4ceaf0bf2e8dc3efbc6e41e608816385f40c04984659b0ec15f109b7a6bf20a"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2073e51c7db7040c6046e36585873a0addc2bcddeb6e944b46f96c607dd83595"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 53 56 57 8B F9 85 D2 74 18 0F B7 02 8D 5A 02 0F B7 72 02 8B 4A 04 3B C7 74 0E 83 C2 08 03 D1 75 E8 33 C0 5F 5E 5B 5D C3 B8 78 03 00 00 66 3B F0 74 EF 8B 45 08 89 18 8D 41 06 EB E7 8D }
    condition:
        all of them
}

rule Windows_Generic_Threat_1417511b {
    meta:
        author = "Elastic Security"
        id = "1417511b-2b31-47a8-8465-b6a174174863"
        fingerprint = "4be19360fccf794ca2e53c4f47cd1becf476becf9eafeab430bdb3c64581613c"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2fc9bd91753ff3334ef7f9861dc1ae79cf5915d79fa50f7104cbb3262b7037da"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 20 8B 45 08 89 45 F4 8B 4D F4 8B 55 08 03 51 3C 89 55 F0 B8 08 00 00 00 6B C8 00 8B 55 F0 8B 45 08 03 44 0A 78 89 45 F8 8B 4D F8 8B 55 08 03 51 20 89 55 EC 8B 45 F8 8B 4D 08 03 }
    condition:
        all of them
}

rule Windows_Generic_Threat_7526f106 {
    meta:
        author = "Elastic Security"
        id = "7526f106-018f-41b9-a1bf-15f7d9f2188e"
        fingerprint = "5f5fc4152aae94b9c3bc0380dbcb093289c840a29b629b1d76a09c672daa9586"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "5a297c446c27a8d851c444b6b32a346a7f9f5b5e783564742d39e90cd583e0f0"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 50 72 6F 6A 65 63 74 31 2E 75 45 78 57 61 74 63 68 }
        $a2 = { 6C 49 45 4F 62 6A 65 63 74 5F 44 6F 63 75 6D 65 6E 74 43 6F 6D 70 6C 65 74 65 }
    condition:
        all of them
}

rule Windows_Generic_Threat_cbe3313a {
    meta:
        author = "Elastic Security"
        id = "cbe3313a-ab8f-4bf1-8f62-b5494c6e7034"
        fingerprint = "dc92cec72728b1df78d79dc5a34ea56ee0b8c8199652c1039288c46859799376"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1ca2a28c851070b9bfe1f7dd655f2ea10ececef49276c998a1d2a1b48f84cef3"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 08 68 E6 25 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 2C 53 56 57 89 65 F8 C7 45 FC D0 25 40 00 A1 94 B1 41 00 33 F6 3B C6 89 75 EC 89 75 E8 89 75 E4 0F 8E E7 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_779cf969 {
    meta:
        author = "Elastic Security"
        id = "779cf969-d1a0-4280-94cb-c7f62d33482c"
        fingerprint = "7e089462cc02e2c9861018df71bf5dda6a3a982d3d98b252d44387c937526be4"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ef281230c248442c804f1930caba48f0ae6cef110665020139f826ab99bbf274"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 3E 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 50 79 74 68 6F 6E 20 53 6F 66 74 77 61 72 65 20 46 6F 75 6E 64 61 74 69 6F 6E 2E 20 41 6C 6C 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 2E }
    condition:
        all of them
}

rule Windows_Generic_Threat_d568682a {
    meta:
        author = "Elastic Security"
        id = "d568682a-94d2-41e7-88db-f6d6499cbdb2"
        fingerprint = "2195cf67cdedfe7531591f65127ef800062d88157126393d0a767837a9023632"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0d98bc52259e0625ec2f24078cf4ae3233e5be0ade8f97a80ca590a0f1418582"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 28 22 00 00 0A 80 19 00 00 04 28 53 00 00 06 28 2D 00 00 0A 28 5D 00 00 06 16 80 1D 00 00 04 7E 13 00 00 04 7E 15 00 00 04 16 7E 15 00 00 04 8E B7 16 14 FE 06 5B 00 00 06 73 79 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_ccb6a7a2 {
    meta:
        author = "Elastic Security"
        id = "ccb6a7a2-6003-4ba0-aefc-3605d085486d"
        fingerprint = "a73b0e067fce2e87c08359b4bb2ba947cc276ff0a07ff9e04cabde529e264192"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "60503212db3f27a4d68bbfc94048ffede04ad37c78a19c4fe428b50f27af7a0d"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 40 52 61 6E 67 65 3A 62 79 74 65 73 3D 30 2D }
        $a2 = { 46 49 77 41 36 4B 58 49 75 4E 66 4B 71 49 70 4B 30 4D 57 4D 74 49 38 4B 67 4D 68 49 39 4B 30 4D 53 49 6A 4B 66 4D 73 49 76 4B 75 4D 64 49 70 4B 30 4D 73 49 66 4B 68 4D 6F 49 69 43 6F 4D 6C 49 71 4B }
    condition:
        all of them
}

rule Windows_Generic_Threat_d62f1d01 {
    meta:
        author = "Elastic Security"
        id = "d62f1d01-4e24-4a93-85ad-3a3886d5de2f"
        fingerprint = "f7736c8920092452ca795583a258ad8b1ffd79116bddde3cff5d06b3ddab31b6"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "380892397b86f47ec5e6ed1845317bf3fd9c00d01f516cedfe032c0549eef239"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 53 56 8B 75 08 33 C0 57 8B FE AB AB AB 8B 7D 0C 8B 45 10 03 C7 89 45 FC 3B F8 73 3F 0F B7 1F 53 E8 01 46 00 00 59 66 3B C3 75 28 83 46 04 02 83 FB 0A 75 15 6A 0D 5B 53 E8 E9 45 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2bb6f41d {
    meta:
        author = "Elastic Security"
        id = "2bb6f41d-41bb-4257-84ef-9026fcc0ebec"
        fingerprint = "d9062e792a0b8f92a03c0fdadd4dd651a0072faa3dd439bb31399a0c75a78c21"
        creation_date = "2024-01-17"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "afa060352346dda4807dffbcac75bf07e8800d87ff72971b65e9805fabef39c0"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 67 65 74 5F 73 45 78 70 59 65 61 72 }
        $a2 = { 73 65 74 5F 73 45 78 70 59 65 61 72 }
        $a3 = { 42 72 6F 77 73 65 72 50 61 74 68 54 6F 41 70 70 4E 61 6D 65 }
    condition:
        all of them
}

rule Windows_Generic_Threat_c54ed0ed {
    meta:
        author = "Elastic Security"
        id = "c54ed0ed-9c63-437c-a016-d960bbb83c40"
        fingerprint = "1e08706e235d6cf23d9c772e1b67463b3e6261a5155d88762472d892079df0d4"
        creation_date = "2024-01-21"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 81 FA 00 10 00 00 72 1C 48 83 C2 27 4C 8B 41 F8 49 2B C8 48 8D 41 F8 48 83 F8 1F 0F 87 92 00 00 00 49 8B C8 ?? ?? ?? ?? ?? 48 83 63 10 00 33 C0 EB 58 4D 8B CC 4D 8B C7 49 8B D6 48 8B CE FF D0 }
    condition:
        all of them
}

rule Windows_Generic_Threat_dbe41439 {
    meta:
        author = "Elastic Security"
        id = "dbe41439-982d-4897-9007-9ad0f206dc75"
        fingerprint = "f7c94f5bc3897c4741899e4f6d2731cd07f61e593500efdd33b5d84693465dd3"
        creation_date = "2024-01-21"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "64afd2bc6cec17402473a29b94325ae2e26989caf5a8b916dc21952149d71b00"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 E4 F8 83 EC 2C 53 56 8B F1 57 89 74 24 10 8B 46 1C 8B 08 85 C9 74 23 8B 56 2C 8B 3A 8D 04 0F 3B C8 73 17 8D 47 FF 89 02 8B 4E 1C 8B 11 8D 42 01 89 01 0F B6 02 E9 F1 00 00 00 33 DB }
    condition:
        all of them
}

rule Windows_Generic_Threat_51a52b44 {
    meta:
        author = "Elastic Security"
        id = "51a52b44-025b-4068-89eb-01cdf66efb4e"
        fingerprint = "b10f3a3ceab827482139a9cadbd4507767e4d941191a7f19af517575435a5f70"
        creation_date = "2024-01-21"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "303aafcc660baa803344bed6a3a7a5b150668f88a222c28182db588fc1e744e0"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 40 6A 67 72 72 6C 6E 68 6D 67 65 77 77 68 74 69 63 6F 74 6D 6C 77 6E 74 6A 6A 71 68 72 68 62 74 75 64 72 78 7A 63 72 67 65 78 65 70 71 73 7A 73 75 78 6B 68 6E 79 63 74 72 63 63 7A 6D 63 63 69 63 61 61 68 70 66 }
    condition:
        all of them
}

rule Windows_Generic_Threat_5c18a7f9 {
    meta:
        author = "Elastic Security"
        id = "5c18a7f9-01af-468b-9a63-cfecbeb739d7"
        fingerprint = "68c9114ac342d527cf6f0cea96b63dfeb8e5d80060572fad2bbc7d287c752d4a"
        creation_date = "2024-01-21"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fd272678098eae8f5ec8428cf25d2f1d8b65566c59e363d42c7ce9ffab90faaa"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 5D E9 CD 1A 00 00 8B FF 55 8B EC 51 FF 75 08 C7 45 FC 00 00 00 00 8B 45 FC E8 03 1B 00 00 59 C9 C3 8B FF 55 8B EC 51 56 57 E8 6B 18 00 00 8B F0 85 F6 74 1C 8B 16 8B CA 8D 82 90 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_ab01ba9e {
    meta:
        author = "Elastic Security"
        id = "ab01ba9e-01e6-405b-8aaf-ae06a8fe2454"
        fingerprint = "dd9feb5d5756b3d3551ae21982b5e6eb189576298697b7d7d4bd042e4fc4c74f"
        creation_date = "2024-01-21"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2b237716d0c0c9877f54b3fa03823068728dfe0710c5b05e9808eab365a1408e"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 53 3C 3B 54 24 38 74 23 45 3B 6C 24 2C }
        $a2 = { 3A 3D 3B 47 3B 55 3B 63 3B 6A 3B 7A 3B }
        $a3 = { 56 30 61 30 6B 30 77 30 7C 30 24 39 32 39 37 39 41 39 4F 39 5D 39 64 39 75 39 }
    condition:
        all of them
}

rule Windows_Generic_Threat_917d7645 {
    meta:
        author = "Elastic Security"
        id = "917d7645-f13e-4d66-ab9e-447a19923ab7"
        fingerprint = "557b459c07dc7d7e32cac389673d5ab487d1730de20a9ec74ae9432325d40cd2"
        creation_date = "2024-01-21"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "19b54a20cfa74cbb0f4724155244b52ca854054a205be6d148f826fa008d6c55"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 E4 E0 56 57 53 81 EC D4 0A 00 00 8B D9 8B F2 BA 1D 00 00 00 FF 73 1C 8D 8C 24 BC 0A 00 00 E8 19 A1 02 00 6A 00 FF B4 24 BC 0A 00 00 8D 8C 24 A8 0A 00 00 E8 D4 06 03 00 8D 8C 24 B8 }
    condition:
        all of them
}

rule Windows_Generic_Threat_7a09e97d {
    meta:
        author = "Elastic Security"
        id = "7a09e97d-ccab-48d7-80d3-d76253a4d7e2"
        fingerprint = "3302bbee32c9968d3131277f4256c5673bec6cc64c1d820a32e66a7313387415"
        creation_date = "2024-01-21"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c0c1e333e60547a90ec9d9dac3fc6698b088769bc0f5ec25883b2c4d1fd680a9"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 06 2A 3A FE 09 00 00 FE 09 01 00 6F 8D 00 00 0A 2A 00 4A FE 09 00 00 FE 09 01 00 FE 09 02 00 6F 8E 00 00 0A 2A 00 1E 00 28 43 00 00 06 2A 5A FE 09 00 00 FE 09 01 00 FE 09 02 00 FE 09 }
    condition:
        all of them
}

rule Windows_Generic_Threat_dc4ede3b {
    meta:
        author = "Elastic Security"
        id = "dc4ede3b-d0c7-4993-8629-88753d65a7ad"
        fingerprint = "8be5afdf2a5fe5cb1d4b50d10e8e2e8e588a72d6c644aa1013dd293c484da33b"
        creation_date = "2024-01-21"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c49f20c5b42c6d813e6364b1fcb68c1b63a2f7def85a3ddfc4e664c4e90f8798"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 89 E5 83 EC 28 C7 45 FC 00 00 00 00 C7 44 24 18 00 00 00 00 C7 44 24 14 00 00 00 00 C7 44 24 10 03 00 00 00 C7 44 24 0C 00 00 00 00 C7 44 24 08 00 00 00 00 C7 44 24 04 00 00 00 80 8B 45 08 }
    condition:
        all of them
}

rule Windows_Generic_Threat_bb480769 {
    meta:
        author = "Elastic Security"
        id = "bb480769-57fb-4c93-8330-450f563fd4c6"
        fingerprint = "9c58c2e028f99737574d49e47feb829058f6082414b58d6c9e569a50904591e7"
        creation_date = "2024-01-21"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "010e3aeb26533d418bb7d2fdcfb5ec21b36603b6abb63511be25a37f99635bce"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 89 E5 C6 45 03 B8 C7 45 08 BA EF BE AD C7 45 0C DE 89 10 BA C7 45 10 EF BE AD DE C7 45 14 89 50 04 B8 C7 45 18 EF BE AD DE C7 45 1C 6A 00 6A 01 C7 45 20 6A 00 FF D0 C7 45 24 B8 EF BE AD C7 }
    condition:
        all of them
}

rule Windows_Generic_Threat_5fbf5680 {
    meta:
        author = "Elastic Security"
        id = "5fbf5680-05c3-4a77-95d7-fa3cae7b4dbe"
        fingerprint = "7cbd8d973f31505e078781bed8067ae8dce72db076c670817e1a77e48dc790fe"
        creation_date = "2024-01-21"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1b0553a9873d4cda213f5464b5e98904163e347a49282db679394f70d4571e77"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 3C 56 57 8B 45 08 50 E8 51 AF 00 00 83 C4 04 89 45 FC 8B 45 FC 83 C0 58 99 8B C8 8B F2 8B 45 08 99 2B C8 1B F2 89 4D F8 66 0F 57 C0 66 0F 13 45 EC C7 45 DC FF FF FF FF C7 45 E0 }
    condition:
        all of them
}

rule Windows_Generic_Threat_aa30a738 {
    meta:
        author = "Elastic Security"
        id = "aa30a738-616b-408c-960f-c0ea897145d0"
        fingerprint = "d2a4e1d4451d28afcef981f689de3212ff5d9c4ee8840864656082ef272f7501"
        creation_date = "2024-01-21"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "7726a691bd6c1ee51a9682e0087403a2c5a798ad172c1402acf2209c34092d18"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 8B 55 0C 85 D2 75 04 33 C0 5D C3 8B 45 08 53 56 8B 75 10 83 FE 08 57 F7 D0 B9 FF 00 00 00 0F 8C D1 00 00 00 8B FE C1 EF 03 8B DF F7 DB 8D 34 DE 89 75 10 0F B6 1A 8B F0 23 F1 33 F3 8B }
    condition:
        all of them
}

rule Windows_Generic_Threat_9a8dc290 {
    meta:
        author = "Elastic Security"
        id = "9a8dc290-d9ec-4d52-a4e8-db4ac6ceb164"
        fingerprint = "e9f42a0fdd778b8619633cce87c9d6a3d26243702cdd8a56e524bf48cf759094"
        creation_date = "2024-01-21"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "d951562a841f3706005d7696052d45397e3b4296d4cd96bf187920175fbb1676"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 6F 01 00 06 FE 0E 0B 00 FE 0C 0B 00 FE 0C 09 00 6F 78 01 00 06 FE 0C 0B 00 FE 0C 08 00 28 F2 00 00 06 6F 74 01 00 06 FE 0C 0B 00 FE 0C 07 00 28 F2 00 00 06 6F 76 01 00 06 FE 0C 0B 00 FE 09 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_bbf2a354 {
    meta:
        author = "Elastic Security"
        id = "bbf2a354-64e5-4115-aaf7-2705194445da"
        fingerprint = "8fb9fcf8b9c661e4966b37a107d493e620719660295b200cfc67fc5533489dee"
        creation_date = "2024-01-22"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b4e6c748ad88070e39b53a9373946e9e404623326f710814bed439e5ea61fc3e"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 54 68 61 74 20 70 72 6F 67 72 61 6D 20 6D 75 73 74 20 62 65 20 72 75 6E 20 75 6E 64 65 72 20 57 69 6E 33 32 }
    condition:
        all of them
}

rule Windows_Generic_Threat_da0f3cbb {
    meta:
        author = "Elastic Security"
        id = "da0f3cbb-e894-48a3-9169-b011e7ab278d"
        fingerprint = "f50116e1f153d2a0e1e2dad879ba8bd6ac9855a563f6cbcbe6b6a06a96e86299"
        creation_date = "2024-01-22"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b2c456d0051ffe1ca7e9de1e944692b10ed466eabb38242ea88e663a23157c58"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 8B 45 0C 53 56 83 F8 FF 57 8B F1 74 03 89 46 10 8B 7D 08 33 DB 3B FB 75 17 FF 76 04 E8 C6 09 00 00 59 89 5E 04 89 5E 0C 89 5E 08 E9 D9 00 00 00 8B 4E 04 3B CB 75 23 8D 1C 3F 53 E8 7E }
    condition:
        all of them
}

rule Windows_Generic_Threat_7d555b55 {
    meta:
        author = "Elastic Security"
        id = "7d555b55-20fb-42d4-b337-c267a34fd459"
        fingerprint = "eedf850c3576425fb37291f954dfa39db758cdad0a38f85581d2bcaedcb54769"
        creation_date = "2024-01-22"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "7efa5c8fd55a20fbc3a270cf2329d4a38f10ca372f3428bee4c42279fbe6f9c3"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 40 53 56 57 6A 0F 59 BE 84 77 40 00 8D 7D C0 8B 5D 0C F3 A5 66 A5 8B CB 33 C0 A4 8B 7D 08 8B D1 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA 33 C0 8D 7D 0E 50 66 AB FF 15 BC 60 40 00 50 }
    condition:
        all of them
}

rule Windows_Generic_Threat_0a38c7d0 {
    meta:
        author = "Elastic Security"
        id = "0a38c7d0-8f5e-4dcf-9aaf-5fcf96451d3c"
        fingerprint = "43998ceb361ecf98d923c0388c00023f19d249a5ac0011dee0924fdff92af42b"
        creation_date = "2024-01-22"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "69ea7d2ea3ed6826ddcefb3c1daa63d8ab53dc6e66c59cf5c2506a8af1c62ef4"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 8B 4D 08 85 C9 74 37 8B 45 0C 3D E0 10 00 00 7C 05 B8 E0 10 00 00 85 C0 7E 24 8D 50 FF B8 AB AA AA AA F7 E2 D1 EA 83 C1 02 42 53 8B FF 8A 41 FE 8A 19 88 59 FE 88 01 83 C1 03 4A 75 F0 }
    condition:
        all of them
}

rule Windows_Generic_Threat_98527d90 {
    meta:
        author = "Elastic Security"
        id = "98527d90-90fb-4428-ab3f-6bbf23139a6e"
        fingerprint = "dac4d9e370992cb4a064d64660801fa165a7e0a1f4a52e9bc3dc286395dcbc91"
        creation_date = "2024-01-24"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fa24e7c6777e89928afa2a0afb2fab4db854ed3887056b5a76aef42ae38c3c82"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 20 FF D5 48 8D 87 0F 02 00 00 80 20 7F 80 60 28 7F 4C 8D 4C 24 20 4D 8B 01 48 89 DA 48 89 F9 FF D5 48 83 C4 28 5D 5F 5E 5B 48 8D 44 24 80 6A 00 48 39 C4 75 F9 48 83 EC 80 E9 8D 70 FC }
    condition:
        all of them
}

rule Windows_Generic_Threat_9f4a80b2 {
    meta:
        author = "Elastic Security"
        id = "9f4a80b2-e1ee-4825-a5e5-79175213da7d"
        fingerprint = "86946aea009f8debf5451ae7894529dbcf79ec104a51590d542c0d64a06f2669"
        creation_date = "2024-01-24"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "47d57d00e2de43f33cd56ff653adb59b804e4dbe37304a5fa6a202ee20b50c24"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 2A 20 02 00 00 00 FE 0E 08 00 00 FE 0C 08 00 20 00 00 00 00 FE 01 39 0A 00 00 00 00 20 01 00 00 00 FE 0E 08 00 00 FE 0C 08 00 20 02 00 00 00 FE 01 39 05 00 00 00 38 05 00 00 00 38 }
    condition:
        all of them
}

rule Windows_Generic_Threat_39e1eb4c {
    meta:
        author = "Elastic Security"
        id = "39e1eb4c-32ba-4c78-9997-1c75b41dcba6"
        fingerprint = "63d21d89b4ceea1fbc44a1dfd2dbb9ac3eb945884726a9809133624b10168c7a"
        creation_date = "2024-01-24"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "a733258bf04ffa058db95c8c908a79650400ebd92600b96dd28ceecac311f94a"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 E4 F8 83 EC 6C 53 56 8B 75 08 57 8B C6 8D 4C 24 58 E8 26 80 00 00 8B C6 8D 4C 24 38 E8 1B 80 00 00 80 7C 24 54 00 8B 7E 0C 8B 5E 08 89 7C 24 1C 74 09 8B 74 24 50 E8 61 80 00 00 83 }
    condition:
        all of them
}

rule Windows_Generic_Threat_d51dd31b {
    meta:
        author = "Elastic Security"
        id = "d51dd31b-1735-4fd7-9906-b07406a9d20c"
        fingerprint = "f313354a52ba8058c36aea696fde5548c7eb9211cac3b6caa511671445efe2a7"
        creation_date = "2024-01-24"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2a61c0305d82b6b4180c3d817c28286ab8ee56de44e171522bd07a60a1d8492d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 7E 7D 7C 7B 7A 79 78 78 76 77 74 73 72 }
        $a2 = { 6D 6C 6B 6A 69 68 67 66 65 64 63 62 61 60 60 5E 66 60 5B 5A }
    condition:
        all of them
}

rule Windows_Generic_Threat_3a321f0a {
    meta:
        author = "Elastic Security"
        id = "3a321f0a-2775-455f-b8c2-30591ebfe4ac"
        fingerprint = "230c3bbc70ec93888f5cd68598dcc004844db67f17d1048a51f6c6408bc4a956"
        creation_date = "2024-01-29"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "91056e8c53dc1e97c7feafab31f0943f150d89a0b0026bcfb3664d2e93ccfe2b"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 44 8D 45 14 8B 4D 10 85 C9 89 5D F8 89 7D FC 0F 8E 3D 01 00 00 49 8D 55 17 83 E2 FC 89 4D 10 85 C9 8D 42 08 8B 58 F8 8B 78 FC 89 5D D4 89 7D D8 0F 8E 31 01 00 00 83 C2 0B 49 83 }
    condition:
        all of them
}

rule Windows_Generic_Threat_a82f45a8 {
    meta:
        author = "Elastic Security"
        id = "a82f45a8-8e47-4966-9d48-9af61a21ac42"
        fingerprint = "e3a1faabc15e2767eb065f4e2a7c6f75590cba1368db1aab1af972a5aeca4031"
        creation_date = "2024-01-29"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ad07428104d3aa7abec2fd86562eaa8600d3e4b0f8d78ba1446f340d10008b53"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 89 4D FC 8B 4D 08 51 8B 4D FC 83 C0 04 E8 66 7D F6 FF 59 5D C2 08 00 90 55 8B EC 51 89 4D FC 8B 4D 08 51 41 51 8B 4D FC E8 CF FF FF FF 59 5D C2 04 00 8B C0 55 8B EC 83 C4 F8 53 56 }
    condition:
        all of them
}

rule Windows_Generic_Threat_d6625ad7 {
    meta:
        author = "Elastic Security"
        id = "d6625ad7-7f2c-4445-a5f2-a9444425f3a4"
        fingerprint = "0e1bb99e22b53e6bb6350f95caaac592ddcad7695e72e298c7ab1d29d1dd4c1f"
        creation_date = "2024-01-29"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "878c9745320593573597d62c8f3adb3bef0b554cd51b18216f6d9f5d1a32a931"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 2E 3F 41 56 3C 6C 61 6D 62 64 61 5F 31 3E 40 3F 4C 40 3F 3F 6F 6E 5F 65 76 65 6E 74 5F 61 64 64 40 43 6F 6D 70 6F 6E 65 6E 74 5F 4B 65 79 6C 6F 67 65 72 40 40 45 41 45 58 49 40 5A 40 }
    condition:
        all of them
}

rule Windows_Generic_Threat_61bbb571 {
    meta:
        author = "Elastic Security"
        id = "61bbb571-8544-4874-9811-bd74a5e9f712"
        fingerprint = "be0b1be30cab0789a5df29153187cf812e53cd35dbe31f9527eca2396d7503b5"
        creation_date = "2024-01-29"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "41e2a6cecb1735e8f09b1ba5dccff3c08afe395b6214396e545347927d1815a8"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 14 8B 45 08 53 56 57 8B F9 BE 49 92 24 09 6A 1C 59 89 7D F8 2B 07 99 F7 F9 89 45 FC 8B 47 04 2B 07 99 F7 F9 89 45 F0 3B C6 0F 84 E5 00 00 00 8D 58 01 8B 47 08 2B 07 99 F7 F9 8B }
    condition:
        all of them
}

rule Windows_Generic_Threat_4a605e93 {
    meta:
        author = "Elastic Security"
        id = "4a605e93-971d-4257-b382-065159840a4c"
        fingerprint = "58185f9fdf5bbc57cd708d8c963a37824e377a045549f2eb78d5fa501082b687"
        creation_date = "2024-01-29"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1a84e25505a54e8e308714b53123396df74df1bde223bb306c0dc6220c1f0bbb"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 20 48 8B 19 45 33 C0 48 85 DB 74 65 4C 89 01 48 83 FA FF 75 17 41 8B C0 44 38 03 74 2D 48 8B CB 48 FF C1 FF C0 44 38 01 75 F6 EB 1E 48 83 FA FE 75 1B 41 8B C0 66 44 39 03 74 0F 48 8B }
    condition:
        all of them
}

rule Windows_Generic_Threat_b509dfc8 {
    meta:
        author = "Elastic Security"
        id = "b509dfc8-6ec3-4315-a1ec-61e6b65793e7"
        fingerprint = "bb1e607fe0d84f25c9bd09d31614310e204dce17c4050be6ce7dc6ed9dfd8f92"
        creation_date = "2024-01-29"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9b5124e5e1be30d3f2ad1020bbdb93e2ceeada4c4d36f71b2abbd728bd5292b8"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 6F 29 00 00 0A 6F 2A 00 00 0A 13 04 11 04 28 22 00 00 0A 28 2B 00 00 0A 2D 0D 11 04 28 22 00 00 0A 28 2C 00 00 0A 26 06 28 2D 00 00 0A 2C 0F 06 73 28 00 00 0A 13 05 11 05 6F 2E 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_7a49053e {
    meta:
        author = "Elastic Security"
        id = "7a49053e-5ae4-4141-9471-4a92e0ee226e"
        fingerprint = "49c41c5372da04b770d903013ee7f71193a4650340fd4245d6d5bceff674d637"
        creation_date = "2024-01-29"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "29fb2b18cfd72a2966640ff59e67c89f93f83fc17afad2dfcacf9f53e9ea3446"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 5D 76 3F 3F 32 40 59 41 50 41 58 49 40 5A 66 }
        $a2 = { 41 75 74 68 6F 72 69 7A 61 26 42 61 73 69 63 48 24 }
        $a3 = { 4A 7E 4C 65 61 76 65 47 65 74 51 75 65 }
    condition:
        all of them
}

rule Windows_Generic_Threat_fca7f863 {
    meta:
        author = "Elastic Security"
        id = "fca7f863-8d5b-4b94-8f60-a72c76782d1d"
        fingerprint = "4b391399465f18b01d7cbdf222dd7249f4fff0a5b4b931e568d92f47cc283a27"
        creation_date = "2024-01-29"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9d0e786dd8f1dc05eae910c6bcf15b5d05b4b6b0543618ca0c2ff3c4bb657af3"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 89 E5 8D 64 24 F4 53 89 C3 6A 0C 8D 45 F4 50 6A 00 FF 53 10 50 FF 53 0C 50 FF 53 24 8B 45 F4 89 43 2C 03 40 3C 8B 40 50 89 43 34 6A 40 68 00 30 00 00 FF 73 34 6A 00 FF 13 89 43 30 8B 4B 34 }
    condition:
        all of them
}

rule Windows_Generic_Threat_cafbd6a3 {
    meta:
        author = "Elastic Security"
        id = "cafbd6a3-c367-467d-b305-fb262e4d6d07"
        fingerprint = "d3237c30fb6eef10b89dc9138572f781cc7d9dad1524e2e27eee82c50f863fbb"
        creation_date = "2024-01-29"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "97081a51aa016d0e6c9ecadc09ff858bf43364265a006db9d7cc133f8429bc46"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 6C 6B 73 6A 66 68 67 6C 6B 6A 66 73 64 67 31 33 31 }
        $a2 = { 72 65 67 20 44 65 6C 65 74 65 20 22 48 4B 4C 4D 5C 53 4F 46 54 57 41 52 45 5C 4D 69 63 72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 20 4E 54 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 52 75 6E 4F 6E 63 65 22 20 2F 66 20 3E 20 6E 75 6C }
    condition:
        all of them
}

rule Windows_Generic_Threat_d8f834a9 {
    meta:
        author = "Elastic Security"
        id = "d8f834a9-41b7-4fc9-8100-87b9b07c0bc7"
        fingerprint = "fcf7fc680c762ffd9293a84c9ac2ba34b18dc928417ebdabd6dfa998f96ed1f6"
        creation_date = "2024-01-29"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c118c2064a5839ebd57a67a7be731fffe89669a8f17c1fe678432d4ff85e7929"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 C4 F4 53 56 57 8B F9 8B F2 8B D8 33 D2 8A 55 08 0F AF 53 30 D1 FA 79 03 83 D2 00 03 53 30 8B 43 34 E8 62 48 04 00 89 45 FC 68 20 00 CC 00 8B 45 20 50 57 56 8B 45 FC 8B 10 FF 52 20 }
    condition:
        all of them
}

rule Windows_Generic_Threat_de3f91c6 {
    meta:
        author = "Elastic Security"
        id = "de3f91c6-bca8-4ed6-8ba3-a53903556903"
        fingerprint = "bd994a85b967e56628a3fcd784e4d73cf6bd9f34a222d1bb52b1e87b775fdd06"
        creation_date = "2024-01-31"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "e2cd4a8ccbf4a3a93c1387c66d94e9506b5981357004929ce5a41fcedfffb20f"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 56 8B 75 08 80 7E 04 00 74 08 FF 36 E8 0B 41 00 00 59 83 26 00 C6 46 04 00 5E 5D C3 55 8B EC 8B 45 08 8B 4D 0C 3B C1 75 04 33 C0 5D C3 83 C1 05 83 C0 05 8A 10 3A 11 75 18 84 D2 74 EC }
    condition:
        all of them
}

rule Windows_Generic_Threat_f0516e98 {
    meta:
        author = "Elastic Security"
        id = "f0516e98-57e1-4e88-b49d-afeff21f6915"
        fingerprint = "c43698c42411080f4df41f0f92948bc5d545f46a060169ee059bb47efefa978c"
        creation_date = "2024-01-31"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "21d01bd53f43aa54f22786d7776c7bc90320ec6f7a6501b168790be46ff69632"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 69 66 20 65 78 69 73 74 20 25 73 20 67 6F 74 6F 20 3A 72 65 70 65 61 74 }
        $a2 = { 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 5F }
    condition:
        all of them
}

rule Windows_Generic_Threat_3c4d9cbe {
    meta:
        author = "Elastic Security"
        id = "3c4d9cbe-700f-4f3e-8e66-d931d5c90d3e"
        fingerprint = "15be51c438b7b2a167e61e35821445404a38c2f8c3e037061a1eba4bf0ded2b5"
        creation_date = "2024-01-31"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "21d01bd53f43aa54f22786d7776c7bc90320ec6f7a6501b168790be46ff69632"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 53 56 57 8B 55 08 8B DA 8B 7A 3C 03 FA 66 81 3F 50 45 75 54 03 5F 78 8B 4B 18 8B 73 20 8B 7B 24 03 F2 03 FA FC 55 8B 6D 0C AD 03 C2 96 87 FD 51 33 C9 80 C1 0F F3 A6 72 0C 96 59 87 FD }
    condition:
        all of them
}

rule Windows_Generic_Threat_deb82e8c {
    meta:
        author = "Elastic Security"
        id = "deb82e8c-57dc-47ea-a786-b4e1ae41a40f"
        fingerprint = "3429ecf8f509c6833b790156e61f0d1a6e0dc259d4891d6150a99b5cb3f0f26e"
        creation_date = "2024-01-31"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0f5791588a9898a3db29326785d31b52b524c3097370f6aa28564473d353cd38"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 50 6F 76 65 72 74 79 20 69 73 20 74 68 65 20 70 61 72 65 6E 74 20 6F 66 20 63 72 69 6D 65 2E }
        $a2 = { 2D 20 53 79 73 74 65 6D 4C 61 79 6F 75 74 20 25 64 }
    condition:
        all of them
}

rule Windows_Generic_Threat_278c589e {
    meta:
        author = "Elastic Security"
        id = "278c589e-fca0-4228-8ffa-6b5e4627b1b1"
        fingerprint = "573b6c5400400b167edd94e12332d421a32dc52138a2a933f2fa85f8409c8e4a"
        creation_date = "2024-01-31"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "cccc6c1bf15a7d5725981de950475e272c277bc3b9d266c5debf0fc698770355"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 49 6E 73 74 61 6C 6C 65 72 20 77 69 6C 6C 20 6E 6F 77 20 64 6F 77 6E 6C 6F 61 64 20 66 69 6C 65 73 20 72 65 71 75 69 72 65 64 20 66 6F 72 20 69 6E 73 74 61 6C 6C 61 74 69 6F 6E 2E }
    condition:
        all of them
}

rule Windows_Generic_Threat_6b621667 {
    meta:
        author = "Elastic Security"
        id = "6b621667-8ed2-4a6e-9fad-fc7a01012859"
        fingerprint = "77d3637fea6d1ddca7b6943671f2d776fa939b063d60d8b659a0fc63acfdc869"
        creation_date = "2024-01-31"
        last_modified = "2024-02-08"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b50b39e460ecd7633a42f0856359088de20512c932fc35af6531ff48c9fa638a"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 64 A1 30 00 00 00 56 33 F6 89 75 FC 8B 40 10 39 70 08 7C 0F 8D 45 FC 50 E8 8F 0D 00 00 83 7D FC 01 74 03 33 F6 46 8B C6 5E C9 C3 8B FF 55 8B EC 51 51 53 56 6A 38 6A 40 E8 32 EB FF }
    condition:
        all of them
}

rule Windows_Generic_Threat_7693d7fd {
    meta:
        author = "Elastic Security"
        id = "7693d7fd-4161-4afb-8a8d-d487f2a7de5e"
        fingerprint = "92489c8eb4f8a9da5e7bd858a47e20b342d70df1ba3a4769df06c434dc83d138"
        creation_date = "2024-02-13"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fc40cc5d0bd3722126302f74ace414e6934eca3a8a5c63a11feada2130b34b89"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 51 8B 45 08 83 65 FC 00 8B 00 0F B7 48 14 66 83 78 06 00 8D 4C 01 18 0F 86 9A 00 00 00 53 56 57 8D 59 24 8B 13 8B CA 8B F2 C1 E9 1D C1 EE 1E 8B FA 83 E1 01 83 E6 01 C1 EF 1F F7 C2 }
    condition:
        all of them
}

rule Windows_Generic_Threat_df5de012 {
    meta:
        author = "Elastic Security"
        id = "df5de012-52b6-4558-a00b-2dbf052e34d3"
        fingerprint = "ee293cda37e0f1c76f89a7d1e074c9591950299b2ae87cca11c6cf7fbfee1fc4"
        creation_date = "2024-02-14"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "13c06d7b030a46c6bb6351f40184af9fafaf4c67b6a2627a45925dd17501d659"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 20 2C 3F 2C 2F 2C 37 2C 27 2C 3B 2C 2B 2C 33 2C 23 2C 3D 2C 2D 2C 35 2C 25 2C 39 2C 29 2C 31 2C 21 2C 3E 2C 2E 2C 36 2C 26 2C 3A 2C 2A 2C 32 2C 22 2C 3C 2C 2C 2C 34 2C 24 2C 38 2C 28 2C 30 2C 20 }
    condition:
        all of them
}

rule Windows_Generic_Threat_0e8530f5 {
    meta:
        author = "Elastic Security"
        id = "0e8530f5-32ce-48a2-9413-5a8f4596ba12"
        fingerprint = "33007c3793c74aaac45434cbd0b524973073a7223d68fae8da5cbd7296120739"
        creation_date = "2024-02-14"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9f44d9acf79ed4450195223a9da185c0b0e8a8ea661d365a3ddea38f2732e2b8"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 63 6D 64 20 2F 63 20 73 74 61 72 74 20 22 22 20 22 25 53 25 53 22 20 25 53 }
        $a2 = { 76 68 61 50 20 71 20 65 71 30 75 61 }
    condition:
        all of them
}

rule Windows_Generic_Threat_ba807e3e {
    meta:
        author = "Elastic Security"
        id = "ba807e3e-13d8-49e0-ad99-32994d490e8b"
        fingerprint = "e6ea7577f8f21e778d21b4651bf55e66ec53fb6d80d68f2ab344261be50d03cc"
        creation_date = "2024-02-14"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "cabd0633b37e6465ece334195ff4cc5c3f44cfe46211165efc07f4073aed1049"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 7D 4A 36 35 2B 7E 2E 2C 2F 37 2C 3D 31 7E 3B 3D 30 30 2F 2A 7E 3C 39 7E 2C 29 30 7E 35 30 7E 5A 4F 4B 7E 31 2F 3A 39 70 }
    condition:
        all of them
}

rule Windows_Generic_Threat_4578ee8c {
    meta:
        author = "Elastic Security"
        id = "4578ee8c-9dfc-4fb2-b5dc-8f55b6ee26d0"
        fingerprint = "3a40e6e8f35c5c114b1b0175723d9403c357bba7170c4350194d40d4a2c94c61"
        creation_date = "2024-02-14"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "699fecdb0bf27994d67492dc480f4ba1320acdd75e5881afbc5f73c982453fed"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 73 65 72 2D 41 67 65 6E 74 3A 4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 25 64 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 25 64 2E 31 3B 20 53 56 31 29 }
    condition:
        all of them
}

rule Windows_Generic_Threat_ebf62328 {
    meta:
        author = "Elastic Security"
        id = "ebf62328-f069-43f2-b943-6ddf64f04fb2"
        fingerprint = "44cce86a986cbb051f1b94c2d5b54830cbe7de1f3387e207bd6b267a5166bbe7"
        creation_date = "2024-02-14"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "dfce19aa2e1a3e983c3bfb2e4bbd7617b96d57602d7a6da6fee7b282e354c9e1"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 74 52 75 50 5B 5D 5F 5E 41 5C 41 5D 41 5E }
        $a2 = { 5F 5E 41 5C 41 5E 41 5F 74 7A 75 78 }
        $a3 = { 44 64 71 52 71 77 7C 61 69 41 66 6E 68 73 6F 72 48 60 6C 65 49 46 }
    condition:
        all of them
}

rule Windows_Generic_Threat_dcc622a4 {
    meta:
        author = "Elastic Security"
        id = "dcc622a4-5c10-463b-a950-fc728f990bca"
        fingerprint = "b47bd4baa68dc56948f29882cf5762b0af2d9f2a837349add4f5d0a8d4152cb2"
        creation_date = "2024-02-14"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "94a3f10396c07783586070119becf0924de9a7caf449d6e07065837d54e6222d"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 5B 21 5D 20 45 72 72 6F 72 20 77 72 69 74 69 6E 67 20 73 68 65 6C 6C 63 6F 64 65 20 74 6F 20 74 68 65 20 74 61 72 67 65 74 20 64 72 69 76 65 72 2C 20 61 62 6F 72 74 }
    condition:
        all of them
}

rule Windows_Generic_Threat_046aa1ec {
    meta:
        author = "Elastic Security"
        id = "046aa1ec-5134-4a03-85c2-048b5d363484"
        fingerprint = "46591671500f83b6627a17368a0bbe43650da1dd58ba1a136a47818fe685bc68"
        creation_date = "2024-02-20"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c74cf499fb9298d43a6e64930addb1f8a8d8336c796b9bc02ffc260684ec60a2"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 C4 F4 D9 7D FE 66 8B 45 FE 80 CC 0C 66 89 45 FC D9 6D FC DF 7D F4 D9 6D FE 8B 45 F4 8B 55 F8 8B E5 5D C3 55 8B EC 51 33 D2 8D 5D 08 8B 03 83 C3 04 85 C0 74 03 03 50 04 49 75 F1 85 }
    condition:
        all of them
}

rule Windows_Generic_Threat_85c73807 {
    meta:
        author = "Elastic Security"
        id = "85c73807-4181-4d4a-ba51-6ed923121486"
        fingerprint = "8b63723aa1b89149c360048900a18e25a0a615f50cec1aaadca2578684f5bcb2"
        creation_date = "2024-02-20"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "7f560a22c1f7511518656ac30350229f7a6847d26e1b3857e283f7dcee2604a0"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 53 56 57 89 4D FC 8B DA 8B F0 8B 7D 08 C6 86 18 01 00 00 00 8B C3 E8 15 01 00 00 84 C0 75 0E 8B 55 FC 8B C6 8B CF E8 45 F8 FF FF EB 0F 56 57 8B FE 8B F3 B9 47 00 00 00 F3 A5 5F 5E }
    condition:
        all of them
}

rule Windows_Generic_Threat_642df623 {
    meta:
        author = "Elastic Security"
        id = "642df623-00ae-48a9-8d61-aaa688606807"
        fingerprint = "fb2c74f7e3e7f4e25173c375fe863e643183da4f5d718d61fdd0271fcc581deb"
        creation_date = "2024-02-20"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "e5ba85d1a6a54df38b5fa655703c3457783f4a4f71e178f83d8aac878d4847da"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 50 B8 04 00 00 00 81 C4 04 F0 FF FF 50 48 75 F6 8B 45 FC 81 C4 3C FE FF FF 53 56 57 64 8B 05 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 8B 00 8B 40 18 89 45 FC 33 C9 8B 45 FC 89 45 DC 8B 45 }
    condition:
        all of them
}

rule Windows_Generic_Threat_27a2994f {
    meta:
        author = "Elastic Security"
        id = "27a2994f-18e4-4608-bda6-ee76b6afd357"
        fingerprint = "33d3f5b2c5fed68b19e14d6a35ee8db4ba3d6d566c87e24fc7a9223235cbd0ee"
        creation_date = "2024-02-20"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "e534914e06d90e119ce87f5abb446c57ec3473a29a7a9e7dc066fdc00dc68adc"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 53 56 57 83 7D 08 00 75 05 E9 88 00 00 00 6A 09 E8 D7 FD FF FF 83 C4 04 8B 45 08 83 E8 20 89 45 FC 8B 4D FC 8B 51 14 81 E2 FF FF 00 00 83 FA 04 74 41 8B 45 FC 83 78 14 01 74 38 8B }
    condition:
        all of them
}

rule Windows_Generic_Threat_dbceec58 {
    meta:
        author = "Elastic Security"
        id = "dbceec58-0b98-470c-8439-23aa26b4064f"
        fingerprint = "5f470a7367ebbffebae8384aa552b3e9b1bda6bf4a3241bda047970341ee7c4c"
        creation_date = "2024-02-20"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fbec30528e6f261aebf0d41f3cd6d35fcc937f1e20e1070f99b1b327f02b91e0"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 14 83 7D 08 00 74 0C 83 7D 0C 00 74 06 83 7D 10 00 75 08 8B 45 08 E9 87 00 00 00 8B 45 08 89 45 FC 8B 45 0C 89 45 F8 8B 45 10 C1 E8 02 89 45 EC 83 65 F4 00 EB 07 8B 45 F4 40 89 }
    condition:
        all of them
}

rule Windows_Generic_Threat_7407eb79 {
    meta:
        author = "Elastic Security"
        id = "7407eb79-69fd-4f5c-b883-ceb74fbdc9d5"
        fingerprint = "f1dbb42fdd80020fa2b30beb50ded6b8b3fe4b023935cef9bd32b3cb0a095654"
        creation_date = "2024-02-20"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9ae0f053c8e2c4f4381eac8265170b79301d4a22ec1fdb86e5eb212c51a75d14"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 18 8B 45 08 8B 40 08 89 45 E8 8B 45 08 8B 40 0C 89 45 EC 8B 45 EC 83 C0 0C 89 45 F0 8B 45 F0 8B 00 89 45 F8 83 65 F4 00 E8 00 00 00 00 58 89 45 F4 8B 45 F8 3B 45 F0 74 31 8B 45 }
    condition:
        all of them
}

rule Windows_Generic_Threat_3613fa12 {
    meta:
        author = "Elastic Security"
        id = "3613fa12-b559-4c3f-8049-11bacd5ffd0c"
        fingerprint = "c66b5dad2e9b19be0bc67a652761d8f79ce85efde055cc412575c2d7c5583795"
        creation_date = "2024-02-20"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1403ec99f262c964e3de133a10815e34d2f104b113b0197ab43c6b7b40b536c0"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 89 4D FC 8D 45 08 50 8B 4D FC E8 4D 03 00 00 8B 45 FC 8B E5 5D C2 04 00 CC CC CC CC 55 8B EC 51 89 4D FC 8B 45 FC 8B E5 5D C3 CC CC 55 8B EC 51 89 4D FC 8B 45 08 50 8B 4D FC E8 FD }
    condition:
        all of them
}

rule Windows_Generic_Threat_b125fff2 {
    meta:
        author = "Elastic Security"
        id = "b125fff2-7b36-431f-8ed3-ccb6d4ff9483"
        fingerprint = "e2562c480b3ab0f0e6c5d396bc5d0584481348c1dd8edaac4484d9cb5d4a2b2e"
        creation_date = "2024-02-20"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9c641c0c8c2fd8831ee4e3b29a2a65f070b54775e64821c50b8ccd387e602097"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 6F 00 00 0A 6F 70 00 00 0A 00 28 24 00 00 06 0A 06 2C 24 00 28 1B 00 00 06 0B 07 2C 19 00 28 CE 04 00 06 16 FE 01 0C 08 2C 0B 7E 03 00 00 04 6F D3 04 00 06 00 00 00 28 1A 00 00 06 00 28 18 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_d7e5ec2d {
    meta:
        author = "Elastic Security"
        id = "d7e5ec2d-bcd1-41a3-80de-12808b9034c9"
        fingerprint = "e679e6917c5055384c0492e4a8a7538b41e5239b78e2167b04fffa3693f036bb"
        creation_date = "2024-02-20"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fe711664a565566cbc710d5e678a9a30063a2db151ebec226e2abcd24c0a7e68"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 C4 F8 89 45 FC 8B 45 FC E8 17 FE FF FF 83 FA 00 75 03 83 F8 FF 77 16 8B 45 FC E8 F1 FE FF FF 83 FA 00 75 03 83 F8 FF 77 04 33 C0 EB 02 B0 01 88 45 FB 8A 45 FB 59 59 5D C3 8D 40 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_1636c2bf {
    meta:
        author = "Elastic Security"
        id = "1636c2bf-5506-4651-9c4c-cd6454386301"
        fingerprint = "b0cd9f484d4191d42091300be33c72a29c073c297b4e46811555fc6d1ab0f482"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "6e43916db43d8217214bbe4eb32ed3d82d0ac423cffc91d053a317a3dbe6dafb"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 28 22 00 00 0A 80 19 00 00 04 28 3B 00 00 06 28 2D 00 00 0A 28 45 00 00 06 16 80 1D 00 00 04 7E 13 00 00 04 7E 15 00 00 04 16 7E 15 00 00 04 8E B7 16 14 FE 06 43 00 00 06 73 63 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_0a640296 {
    meta:
        author = "Elastic Security"
        id = "0a640296-0813-4cd3-b55b-01b3689e73d9"
        fingerprint = "3fa8712dbf0cdb0581fc312bcfa2e9ea50e04cccba6dc93f377c1b64e96784aa"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "3682eff62caaf2c90adef447d3ff48a3f9c34c571046f379d2eaf121976f1d07"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 02 7B 0F 00 00 04 6F 29 00 00 0A 7D 10 00 00 04 02 7B 10 00 00 04 28 2A 00 00 0A 00 02 7B 08 00 00 04 7B 03 00 00 04 02 7B 10 00 00 04 6F 2B 00 00 0A 16 FE 01 0D 09 39 29 01 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_b1ef4828 {
    meta:
        author = "Elastic Security"
        id = "b1ef4828-10bd-41f8-84b5-041bf3147c0b"
        fingerprint = "e867d9a0a489d95898f85578c71d7411eac3142539fcc88df51d1cf048d351a9"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "29b20ff8ebad05e4a33c925251d08824ca155f5d9fa72d6f9e359e6ec6c61279"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 70 36 72 20 74 24 76 28 78 2C 7A 30 7C 34 7E 38 7E 3C 7E 40 7E 54 7E 74 7E 7C 5D }
        $a2 = { 7E 30 7E 34 7E 43 7E 4F 7E 5A 7E 6E 7E 79 7E }
    condition:
        all of them
}

rule Windows_Generic_Threat_48cbdc20 {
    meta:
        author = "Elastic Security"
        id = "48cbdc20-386a-491e-8407-f7c4c348f2e9"
        fingerprint = "98db38ebd05e99171489828491e6acfc7c4322283b325ed99429f366b0ee01a6"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "7a7704c64e64d3a1f76fc718d5b5a5e3d46beeeb62f0493f22e50865ddf66594"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 5E 69 69 69 4E 42 42 42 3E 2E 2E 2E 25 }
        $a2 = { 24 2E 2E 2E 2F 41 41 41 3A 51 51 51 47 5D 5D 5D 54 69 69 69 62 }
    condition:
        all of them
}

rule Windows_Generic_Threat_420e1cdc {
    meta:
        author = "Elastic Security"
        id = "420e1cdc-2d47-437a-986d-ff22d2fac978"
        fingerprint = "33f35c5c73656fc5987c39fabefa1225fef1734f4217518a1b6e7a78669c90c5"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b20254e03f7f1e79fec51d614ee0cfe0cb87432f3a53cf98cf8c047c13e2d774"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 56 8B 75 08 85 F6 74 5A ?? ?? ?? ?? ?? 83 F8 03 75 16 56 E8 ED 01 00 00 59 85 C0 56 74 36 50 E8 0C 02 00 00 59 59 EB 3A 83 F8 02 75 26 8D 45 08 50 8D 45 FC 50 56 E8 25 0F 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_4c37e16e {
    meta:
        author = "Elastic Security"
        id = "4c37e16e-b7ca-449a-a09f-836706b2f66a"
        fingerprint = "9fbd2883fb0140de50df755f7099a0dc3cf377ee350710108fef96c912f43460"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "d83a8ed5e192b3fe9d74f3a9966fa094d23676c7e6586c9240d97c252b8e4e74"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 2E 3F 41 56 43 44 72 6F 70 41 70 69 40 40 }
        $a2 = { 2D 2D 77 77 6A 61 75 67 68 61 6C 76 6E 63 6A 77 69 61 6A 73 2D 2D }
    condition:
        all of them
}

rule Windows_Generic_Threat_5be3a474 {
    meta:
        author = "Elastic Security"
        id = "5be3a474-d12f-489f-a2a7-87d29687e2e6"
        fingerprint = "8b220ea86ad3bbdcf6e2f976dc0bb84c1eb8cb1f3ad46ab5c9d19289952c912b"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b902954d634307260d5bd8fb6248271f933c1cbc649aa2073bf05e79c1aedb66"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 53 56 57 8B F9 33 F6 8D 5F 02 66 8B 07 83 C7 02 66 3B C6 75 F5 8A 01 2B FB D1 FF 8D 5F FF 85 DB 7E 23 0F B6 F8 83 C1 02 66 8B 01 8D 49 02 66 2B C7 C7 45 FC 00 08 00 00 66 2B 45 FC }
    condition:
        all of them
}

rule Windows_Generic_Threat_b191061e {
    meta:
        author = "Elastic Security"
        id = "b191061e-7b83-4161-a1d4-05ab70ffe2be"
        fingerprint = "5733de0357a6b5f6a3fe885786084c23707266b48e67b19dcddc48ed97e94207"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "bd4ef6fae7f29def8e5894bf05057653248f009422de85c1e425d04a0b2df258"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 2C 64 A1 30 00 00 00 33 D2 53 56 57 8B 40 0C 8B F2 89 4D E8 89 55 F4 89 75 F8 8B 58 0C 8B 7B 18 89 7D F0 85 FF 0F 84 34 01 00 00 C7 45 E0 60 00 00 00 8B 43 30 89 55 FC 89 55 EC }
    condition:
        all of them
}

rule Windows_Generic_Threat_05f52e4d {
    meta:
        author = "Elastic Security"
        id = "05f52e4d-d131-491a-a037-069b450e3b3e"
        fingerprint = "f3d5f6dc1f9b51ce1700605c8a018000124d66a260771de0da1a321dc97872dd"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "e578b795f8ed77c1057d8e6b827f7426fd4881f02949bfc83bcad11fa7eb2403"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 06 73 45 00 00 0A 73 46 00 00 0A 6F 47 00 00 0A 14 FE 06 29 00 00 06 73 45 00 00 0A 73 46 00 00 0A 0B 14 FE 06 2A 00 00 06 73 45 00 00 0A 73 46 00 00 0A 0C 07 6F 47 00 00 0A 08 6F 47 }
    condition:
        all of them
}

rule Windows_Generic_Threat_c34e19e9 {
    meta:
        author = "Elastic Security"
        id = "c34e19e9-c666-4fc5-bbb3-75f64d247899"
        fingerprint = "148ffb1f73a3f337d188c78de638880ea595a812dfa7a0ada6dc66805637aeb3"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "f9048348a59d9f824b45b16b1fdba9bfeda513aa9fbe671442f84b81679232db"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 73 18 00 00 0A 7E 02 00 00 04 17 8D 3A 00 00 01 25 16 1F 2C 9D 6F 28 00 00 0A 8E 69 6F 29 00 00 0A 9A 0A 7E 01 00 00 04 17 8D 3A 00 00 01 25 16 1F 2C 9D 6F 28 00 00 0A 73 18 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_e691eaa1 {
    meta:
        author = "Elastic Security"
        id = "e691eaa1-06fa-478e-8c4c-95a7df3fd077"
        fingerprint = "b940eb10e338f6d703a75cd77b4b455503ae0583f5a36b8115e659d05990fc3c"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "afa5f36860e69b9134b93e9ad32fed0a5923772e701437e1054ea98e76f28a77"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 8B C2 53 89 45 FC 8B D9 56 99 33 F6 2B C2 57 8B F8 D1 FF 85 FF 7E 2B 8B 55 FC 4A 03 D3 0F B6 02 8D 52 FF 8A 0C 1E ?? ?? ?? ?? ?? ?? ?? 88 04 1E 46 0F B6 C1 }
    condition:
        all of them
}

rule Windows_Generic_Threat_5e33bb4b {
    meta:
        author = "Elastic Security"
        id = "5e33bb4b-830e-4814-b6cf-d5e5b4da7ada"
        fingerprint = "a08b9db015f1b6f62252d456b1b0cd0fdec1e19cdd2bc1400fe2bf76150ea07b"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "13c06d7b030a46c6bb6351f40184af9fafaf4c67b6a2627a45925dd17501d659"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 43 3A 5C 55 73 65 72 73 5C 61 64 6D 69 6E 5C 44 65 73 6B 74 6F 70 5C 57 6F 72 6B 5C 46 69 6C 65 49 6E 73 74 61 6C 6C 65 72 5C 52 65 6C 65 61 73 65 5C 46 69 6C 65 49 6E 73 74 61 6C 6C 65 72 2E 70 64 62 }
    condition:
        all of them
}

rule Windows_Generic_Threat_be64ba10 {
    meta:
        author = "Elastic Security"
        id = "be64ba10-ea9d-45df-8c9b-2facc825b652"
        fingerprint = "9496099988cf4f854bf7f70bae158c6e17025a7537245c5f1d92a90f6b9bca67"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "24bb4fc117aa57fd170e878263973a392d094c94d3a5f651fad7528d5d73b58a"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 22 65 6E 63 72 79 70 74 65 64 5F 6B 65 79 22 3A 22 28 2E 2B 3F 29 22 }
        $a2 = { 2E 3F 41 56 3C 6C 61 6D 62 64 61 5F 37 65 66 38 63 66 32 36 39 61 32 32 38 62 36 30 34 64 36 35 34 33 32 65 37 65 63 33 37 30 31 34 3E 40 40 }
    condition:
        all of them
}

rule Windows_Generic_Threat_7bb75582 {
    meta:
        author = "Elastic Security"
        id = "7bb75582-ffcd-4a91-8816-811a3f9bdec8"
        fingerprint = "326a08e467cbedb01c640232ad2f4da729894f09ccf5faba93926e1efded9b59"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "35f9698e9b9f611b3dd92466f18f97f4a8b4506ed6f10d4ac84303177f43522d"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 4B 45 59 5F 43 55 52 52 45 4E 54 5F 55 53 45 52 5C 53 6F 66 74 77 61 72 65 5C 4D 69 63 72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 49 6E 74 65 72 6E 65 74 20 53 65 74 74 69 6E 67 73 5C 43 6F 6E 6E 65 63 74 69 6F 6E 73 20 5B 31 20 37 20 31 37 5D }
    condition:
        all of them
}

rule Windows_Generic_Threat_59698796 {
    meta:
        author = "Elastic Security"
        id = "59698796-0022-486a-a743-6931745f38a0"
        fingerprint = "9260d02c3e6b163fd376445bd2a9c084ed85a5dbaf0509e15fff4e9c3d147f19"
        creation_date = "2024-03-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "35f9698e9b9f611b3dd92466f18f97f4a8b4506ed6f10d4ac84303177f43522d"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 81 EC B8 04 00 00 ?? ?? ?? ?? ?? 33 C5 89 45 FC 56 68 00 04 00 00 0F 57 C0 C7 45 F8 00 00 00 00 8D 85 58 FB FF FF C7 85 54 FB FF FF 24 00 00 00 6A 00 50 8B F1 0F 11 45 D8 0F 11 45 E8 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2ae9b09e {
    meta:
        author = "Elastic Security"
        id = "2ae9b09e-b810-4bd2-9cb8-18b1d504eede"
        fingerprint = "13ab32abf52bca58dfac79c09882ec4cb80b606693db19813d84e625bda93549"
        creation_date = "2024-03-05"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "dc8f4784c368676cd411b7d618407c416d9e56d116dd3cd17c3f750e6cb60c40"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 51 8B 45 08 89 45 FC 8B 45 0C 89 45 F8 8B 45 0C 48 89 45 0C 83 7D F8 00 76 0F 8B 45 FC C6 00 00 8B 45 FC 40 89 45 FC EB DE 8B 45 08 C9 C3 6A 41 5A 0F B7 C1 66 3B D1 77 0C 66 83 F9 }
    condition:
        all of them
}

rule Windows_Generic_Threat_604a8763 {
    meta:
        author = "Elastic Security"
        id = "604a8763-7ec1-4474-b238-2ebbaf24afa2"
        fingerprint = "c74c1dc7588d01112c3995b17e9772af15fb1634ebfb417b8c0069ac1f334e74"
        creation_date = "2024-03-05"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2a51fb11032ec011448184a4f2837d05638a7673d16dcf5dcf4005de3f87883a"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 8B 45 0C 48 89 45 FC EB 07 8B 45 FC 48 89 45 FC 83 7D FC 00 7C 0B 8B 45 08 03 45 FC C6 00 00 EB E8 C9 C3 55 8B EC 83 EC 0C 8B 45 0C 89 45 FC 8B 45 08 3B 45 10 76 2F 8B 45 FC 89 45 }
    condition:
        all of them
}

rule Windows_Generic_Threat_f45b3f09 {
    meta:
        author = "Elastic Security"
        id = "f45b3f09-4203-41f7-870e-d8ef5126c391"
        fingerprint = "dfa72e0780e895ab5aa2369a425c64144e9bd435e55d8a0fefbe08121ae31df5"
        creation_date = "2024-03-05"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "577f1dbd76030c7e44ed28c748551691d446e268189af94e1fa1545f06395178"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 33 ED 44 8B ED 48 89 6C 24 78 44 8B FD 48 89 AC 24 88 00 00 00 44 8B F5 44 8B E5 E8 43 04 00 00 48 8B F8 8D 75 01 ?? ?? ?? ?? ?? 66 39 07 75 1A 48 63 47 3C 48 8D 48 C0 }
    condition:
        all of them
}

rule Windows_Generic_Threat_3f390999 {
    meta:
        author = "Elastic Security"
        id = "3f390999-601f-464e-8982-09553adee303"
        fingerprint = "ccfd5fb305ea48d66f299311c5332587355258bdeeb25cb90c450e8e96df3052"
        creation_date = "2024-03-05"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1b6fc4eaef3515058f85551e7e5dffb68b9a0550cd7f9ebcbac158dac9ababf1"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 10 48 89 D9 48 8B 59 10 FF 61 08 0F 1F 40 00 49 89 CB C3 49 89 CA 41 8B 43 08 41 FF 23 C3 90 48 C1 E1 04 31 C0 81 E1 F0 0F 00 00 49 01 C8 4C 8D 0C 02 4E 8D 14 00 31 C9 45 8A 1C 0A 48 }
    condition:
        all of them
}

rule Windows_Generic_Threat_abd1c09d {
    meta:
        author = "Elastic Security"
        id = "abd1c09d-ec66-45ee-b435-302c736cc1f9"
        fingerprint = "2f75d8fa11f67f983e40ada50a07e8a6f1b6dfc663524e35a6526381e939d39f"
        creation_date = "2024-03-05"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "3ff09d2352c2163465d8c86f94baa25ba85c35698a5e3fbc52bc95afc06b7e85"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 0C 8B D1 53 56 57 8B 7D 0C 83 FF 08 77 1A 85 FF 74 16 8B 5D 08 8B 4A 14 8B 72 10 2B CE 8D 04 3B 3B C1 72 11 C6 42 44 00 33 C0 33 D2 5F 5E 5B 8B E5 5D C2 08 00 0F 57 C0 66 0F 13 }
    condition:
        all of them
}

rule Windows_Generic_Threat_b7870213 {
    meta:
        author = "Elastic Security"
        id = "b7870213-e235-4b2d-83c1-e3c7c486ee8d"
        fingerprint = "c087f84c8572dba64da62c9f317969cbce46e78656e0a75489788add787c2781"
        creation_date = "2024-03-05"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "04cb0d5eecea673acc575e54439398cc00e78cc54d8f43c4b9bc353e4fc4430d"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 75 28 6B 6E 4E 30 30 30 31 30 32 30 33 30 34 30 35 30 36 30 37 30 38 30 39 31 30 31 31 31 32 31 33 31 34 31 35 31 36 31 37 31 38 31 39 32 30 32 31 32 32 32 33 32 34 32 35 32 36 32 37 32 38 32 39 33 30 33 31 33 32 33 33 33 34 33 35 33 36 33 37 33 38 33 39 34 30 34 31 34 32 34 33 34 34 34 35 34 36 34 37 34 38 34 39 35 30 35 31 35 32 35 33 35 34 35 35 35 36 35 37 35 38 35 39 36 30 36 31 36 32 36 33 36 34 36 35 36 36 36 37 36 38 36 39 37 30 37 31 37 32 37 33 37 34 37 35 37 36 37 37 37 38 37 39 38 30 38 31 38 32 38 33 38 34 38 35 38 36 38 37 38 38 38 39 39 30 39 31 39 32 39 33 39 34 39 35 39 36 39 37 39 38 39 39 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2bba6bae {
    meta:
        author = "Elastic Security"
        id = "2bba6bae-7c6a-4b89-83d8-0656d7863820"
        fingerprint = "85dc02cb74c481b5ecb144280827add9665138f0b5d479db5468a94b41e662a3"
        creation_date = "2024-03-05"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "d9955c716371422750b77d64256dade6fbd028c8d965db05c0d889d953480373"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 36 35 20 37 39 20 34 31 20 36 39 20 36 34 20 34 38 20 36 43 20 37 37 20 34 39 20 36 41 20 36 46 20 36 37 20 34 39 20 36 42 20 37 30 20 35 38 20 35 36 20 34 33 20 34 39 20 37 33 20 34 39 20 34 33 20 34 41 20 36 38 20 36 32 20 34 37 20 36 33 20 36 39 20 34 46 20 36 39 20 34 31 20 36 39 20 35 32 20 35 37 20 35 32 20 34 35 20 35 35 20 33 30 20 34 35 20 36 39 20 34 39 20 34 38 20 33 30 }
    condition:
        all of them
}

rule Windows_Generic_Threat_4db75701 {
    meta:
        author = "Elastic Security"
        id = "4db75701-e7d6-4231-ba00-e127da90bfce"
        fingerprint = "d8637b329a212bf37367ba3cc3acf65c9b511d1f06d689d792c519324459530d"
        creation_date = "2024-03-05"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fa7847d21d5a350cf96d7ecbcf13dce63e6a0937971cfb479700c5b31850bba9"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 81 EC D0 02 00 00 80 79 20 08 41 8B F1 45 8B F0 4C 8B FA 48 8B F9 0F 84 3A 01 00 00 48 89 58 10 48 89 68 18 43 8D 04 40 48 63 C8 ?? ?? ?? ?? ?? 48 8D 8C 24 20 02 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_54a914c9 {
    meta:
        author = "Elastic Security"
        id = "54a914c9-1b00-4cea-9b82-f7ed1df1305f"
        fingerprint = "d3f4083c96130031ce9656ea31bf0914080c88f09c05f8b1168c60487af80c9b"
        creation_date = "2024-03-25"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c418c5ad8030985bb5067cda61caba3b7a0d24cb8d3f93fc09d452fbdf4174ec"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 20 48 89 CB 48 8B 43 08 4C 8B 48 30 4D 85 C9 74 16 48 8D 4B 10 0F B6 D2 48 83 C4 20 5B 5E 5F 5D 41 5C 49 FF E1 66 90 44 0F B6 40 10 41 80 F8 16 0F 84 81 00 00 00 41 80 F8 18 74 0B 48 }
    condition:
        all of them
}

rule Windows_Generic_Threat_38a88967 {
    meta:
        author = "Elastic Security"
        id = "38a88967-db0e-4d68-9295-9108cbc98fb9"
        fingerprint = "1fef2c4c2899bbf9f45732d23654f6437658de2c4dc78dc3d1ff5440b5c2cbcf"
        creation_date = "2024-03-25"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "6e425eb1a27c4337f05d12992e33fe0047e30259380002797639d51ef9509739"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 60 E8 00 00 00 00 5B ?? ?? ?? ?? ?? ?? 8B 75 08 8B 7D 0C AD 50 53 89 C1 29 DB 29 C0 AC C1 E3 04 01 C3 AA 89 D8 ?? ?? ?? ?? ?? 85 C0 74 07 89 C2 C1 EA 18 31 D3 F7 D0 21 C3 E2 DF 87 DA }
    condition:
        all of them
}

rule Windows_Generic_Threat_e8abb835 {
    meta:
        author = "Elastic Security"
        id = "e8abb835-f0c1-4e27-a0ca-3a3cae3362df"
        fingerprint = "ca8c2f4b16ebe1bb48c91a536d8aca98bed5592675eff9311e77d7e06dfe3c5b"
        creation_date = "2024-03-26"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "e42262671325bec300afa722cefb584e477c3f2782c8d4c6402d6863df348cac"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 81 EC 28 05 00 00 66 44 0F 7F 84 24 10 05 00 00 66 0F 7F BC 24 00 05 00 00 0F 29 B4 24 F0 04 00 00 44 89 44 24 74 48 89 94 24 C8 00 00 00 48 89 CB 48 C7 44 24 78 00 00 00 00 0F 57 F6 0F 29 }
    condition:
        all of them
}

rule Windows_Generic_Threat_492d7223 {
    meta:
        author = "Elastic Security"
        id = "492d7223-4e03-4a77-83e5-ed85e052f846"
        fingerprint = "71a1bce450522a0a6ff38d2f84ab91e2e9db360736c2f7233124a0b0dc4d0431"
        creation_date = "2024-03-26"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c0d9c9297836aceb4400bcb0877d1df90ca387f18f735de195852a909c67b7ef"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 89 E5 53 57 56 83 EC 24 ?? ?? ?? ?? ?? 31 C9 85 C0 0F 94 C1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 C8 40 FF E0 }
    condition:
        all of them
}

rule Windows_Generic_Threat_ea296356 {
    meta:
        author = "Elastic Security"
        id = "ea296356-6533-4364-8ad1-3bbb538e3d61"
        fingerprint = "a17ca2f95473517428867b4f68b8275ae84ef1ee39421e76887077e206b1ed51"
        creation_date = "2024-05-22"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "4c48a0fe90f3da7bfdd32961da7771a0124b77e1ac1910168020babe8143e959"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 83 EC 0C 53 56 8B 75 08 8B C6 89 55 FC 99 2B C2 89 4D F8 8B D8 8B 45 FC 57 D1 FB 33 FF 8D 14 30 89 55 08 85 DB 7E 36 4A 0F 1F 44 00 00 8A 0C 38 8D 52 FF 0F B6 42 01 8B 75 FC 0F B6 80 }
    condition:
        all of them
}

rule Windows_Generic_Threat_aeaeb5cf {
    meta:
        author = "Elastic Security"
        id = "aeaeb5cf-2683-4a88-b736-4b8873d92fc5"
        fingerprint = "f6d32006747b083632f551c8ca182b6b4d67a8f130a118e61b0dd2f35d7d8477"
        creation_date = "2024-05-22"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "f57d955d485904f0c729acff9db1de9cb42f32af993393d58538f07fa273b431"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 8B 4D 08 33 C0 66 39 01 74 0B 8D 49 00 40 66 83 3C 41 00 75 F8 8D 04 45 02 00 00 00 50 FF 75 0C 51 ?? ?? ?? ?? ?? 83 C4 0C 5D C3 CC CC 55 8B EC 6A 00 FF 75 08 }
    condition:
        all of them
}

rule Windows_Generic_Threat_c8424507 {
    meta:
        author = "Elastic Security"
        id = "c8424507-34e1-4649-a4e4-3e0a0f62dfb0"
        fingerprint = "8dfb14903b32c118492ae7e0aab9cf634c58ea93fcbc7759615209f61b3b3d6b"
        creation_date = "2024-05-22"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "d556b02733385b823cfe4db7e562e90aa520e2e6fb00fceb76cc0a6a1ff47692"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 78 75 73 65 68 6F 62 69 6D 6F 7A 61 63 6F 67 6F 6A 69 68 6F 67 69 76 6F }
        $a2 = { 62 65 6D 69 74 69 76 65 67 69 77 6F 6D 65 7A 75 76 65 62 61 67 }
    condition:
        all of them
}

rule Windows_Generic_Threat_9af87ddb {
    meta:
        author = "Elastic Security"
        id = "9af87ddb-c3ed-44a5-b1a1-984b6f8a6065"
        fingerprint = "1505b6299961c729077ffd90a4c7ed3180f55329952841fe7045056ea2919de8"
        creation_date = "2024-05-23"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b1fbc11744e21dc08599412887a3a966572614ce25ccd3c8c98f04bcbdda3898"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 28 2C 00 00 06 11 06 17 D6 13 06 11 06 11 07 8E B7 32 98 06 17 D6 0A 20 E8 03 00 00 28 21 00 00 0A 7E 0F 00 00 04 3A 74 FF FF FF 2A 00 1B 30 04 00 96 00 00 00 1F 00 00 11 03 39 88 }
    condition:
        all of them
}

rule Windows_Generic_Threat_d7b57912 {
    meta:
        author = "Elastic Security"
        id = "d7b57912-02b4-421a-8f93-9e8371314e68"
        fingerprint = "36a3fecc918cd891d9c779f7ff54019908ba190853739c8059adb84233643a1c"
        creation_date = "2024-05-23"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0906599be152dd598c7f540498c44cc38efe9ea976731da05137ee6520288fe4"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 83 C4 B8 53 56 8B DA 89 45 FC 8D 45 FC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 FF 30 64 89 20 8B C3 ?? ?? ?? ?? ?? 6A 00 6A 00 8D 45 F0 50 8B 45 FC }
    condition:
        all of them
}

rule Windows_Generic_Threat_23d33b48 {
    meta:
        author = "Elastic Security"
        id = "23d33b48-00f6-487f-a3e5-f41603fc982e"
        fingerprint = "7a25301a1297337810240e8880febe525726c9b79a4a4bd81b1f856865097995"
        creation_date = "2024-06-05"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "acbc22df07888498ae6f52f5458e3fb8e0682e443a8c2bc97177a0320b4e2098"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 83 7A 14 10 8B C2 53 56 57 8B F1 72 02 8B 02 83 7E 14 10 72 02 8B 0E 8B 5A 10 8D 56 10 8B 3A 53 50 89 55 FC 8B D7 51 ?? ?? ?? ?? ?? 8B D0 83 C4 0C 83 FA FF 74 30 3B FA 72 33 8B C7 }
    condition:
        all of them
}

rule Windows_Generic_Threat_4b0b73ce {
    meta:
        author = "Elastic Security"
        id = "4b0b73ce-960d-40ce-ae85-5cf38d949f45"
        fingerprint = "11c544f9f3a51ffcd361d6558754a64a8a38f3ce9385038880ab58c99769db88"
        creation_date = "2024-06-05"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "236fc00cd7c75f70904239935ab90f51b03ff347798f56cec1bdd73a286b24c1"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 53 56 57 8B 7D 08 83 7F 18 00 C6 45 FF C9 74 54 ?? ?? ?? ?? ?? ?? 8D 9B 00 00 00 00 33 F6 83 7F 18 00 74 40 6A 0A FF D3 46 81 FE E8 03 00 00 7C ED 8B 07 8B 50 08 6A 01 8D 4D FF 51 }
    condition:
        all of them
}

rule Windows_Generic_Threat_1f2e969c {
    meta:
        author = "Elastic Security"
        id = "1f2e969c-5d90-4bab-a06a-9cccb1946251"
        fingerprint = "e7c872f2422fe54367900d69c9bb94d86db2bf001cbbe00ba6c801fb3d1e610e"
        creation_date = "2024-06-05"
        last_modified = "2024-06-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "7def75df729ed66511fbe91eadf15bc69a03618e78c48e27c35497db2a6a97ae"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 53 8B 5A 10 56 8B F1 57 6A 78 89 75 FC C7 46 10 00 00 00 00 C7 46 14 0F 00 00 00 53 89 75 FC C6 06 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 33 C0 89 7D FC 85 DB 7E 39 0F 1F 40 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_27c975fd {
    meta:
        author = "Elastic Security"
        id = "27c975fd-a448-4a11-9dd1-47b242289175"
        fingerprint = "bc82fc2f745c744708269a7d98ba43d4059cf511c278c7b03f791001ba6830e8"
        creation_date = "2024-10-10"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0108af363959f90919f24220caf426fba50be3d61f3735bb0f2acbbcc1f56e0c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 8B EC 83 6D 0C 01 75 1B FF 75 08 ?? ?? ?? ?? ?? ?? 33 C0 50 50 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C0 40 5D C2 0C 00 55 8B EC 83 EC 10 ?? ?? ?? ?? ?? 33 C5 89 45 FC 53 8B D9 }
    condition:
        all of them
}

rule Windows_Generic_Threat_d170474c {
    meta:
        author = "Elastic Security"
        id = "d170474c-7d9b-4f19-8166-b2c96a8a90b8"
        fingerprint = "acc79131046a279c4a0746703649870fe8c88025ec0d370ee68f34cbdbf3d7b6"
        creation_date = "2024-10-10"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "63da7ea6d4cd240485ad5c546dd60b90cb98d6f4f18df4bc708f5ec689be952f"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 02 00 06 6F 36 03 00 06 11 00 28 DC 00 00 06 02 03 11 00 73 7E 00 00 06 13 01 7E 64 00 00 04 13 0F 16 13 03 11 03 11 0F 8E 69 2F 22 11 0F 11 03 9A 13 04 11 04 12 01 6F 83 00 00 06 DE 08 13 }
    condition:
        all of them
}

rule Windows_Generic_Threat_f57e5e2a {
    meta:
        author = "Elastic Security"
        id = "f57e5e2a-9a40-4131-9ed6-f9dbc88b47cf"
        fingerprint = "6066662bd5370557e8f965a3d08ff4bfb97dd78b1fd4a06b78be4b30ba976243"
        creation_date = "2024-10-10"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "bff5112830cc3547c206fb1d028c592a11a3c7cd457ef445b765af86a1e76001"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 89 E5 56 57 8B 75 08 8B 4D 0C E8 00 00 00 00 58 83 C0 2A 83 EC 08 89 E2 C7 42 04 33 00 00 00 89 02 E8 0E 00 00 00 66 8C D9 8E D1 83 C4 14 5F 5E 5D C2 08 00 8B 3C 24 FF 2A 48 31 C0 57 FF D6 }
    condition:
        all of them
}

rule Windows_Generic_Threat_4fe0deb6 {
    meta:
        author = "Elastic Security"
        id = "4fe0deb6-02ed-4530-8574-bf5c8e1094f7"
        fingerprint = "2c6f78007df750d4c4cf4ec42f023ab6b5e1a2307a9b19f6c7b818106c0115d2"
        creation_date = "2024-10-10"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "5836ef66985e851b37a369b04cce579afdb3b241d46a096bf8b1e8d4df053cd2"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC DD 45 08 B9 00 00 F0 7F D9 E1 B8 00 00 F0 FF 39 4D 14 75 3B 83 7D 10 00 75 75 D9 E8 D8 D1 DF E0 F6 C4 05 7A 0F DD D9 DD D8 DD 05 A8 B7 44 00 E9 E9 00 00 00 D8 D1 DF E0 DD D9 F6 C4 41 }
    condition:
        all of them
}

rule Windows_Generic_Threat_c9003b7b {
    meta:
        author = "Elastic Security"
        id = "c9003b7b-2e04-429c-a147-33aeb3e474ac"
        fingerprint = "3e0437dbb5534dfd9f5ee68c50b0f868a88fadc0ded897cb595239456ae3bbb3"
        creation_date = "2024-10-10"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ff2a1def8c4fae4166e249edab62d73f44ba3c05d5e3c9fda11399bfe1fcee6c"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 81 EC B8 01 00 00 49 89 CE 4C 8B 41 28 48 8B 51 48 E8 FE FE FF FF 48 89 C6 4D 8B 46 28 49 8B 56 50 4C 89 F1 E8 EB FE FF FF 48 89 C7 4D 8B 46 28 49 8B 96 E8 01 00 00 4C 89 F1 E8 D5 FE FF FF }
    condition:
        all of them
}

rule Windows_Generic_Threat_21253888 {
    meta:
        author = "Elastic Security"
        id = "21253888-06dd-4e03-bd02-e3dedd322133"
        fingerprint = "5d74ca16c8e4b81c8aba0942496092521dc9d93e82d1922630cb03ea4e988946"
        creation_date = "2024-10-11"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "95e523f4003a10a906ef7c68a258d402e25f235fa9f2b022faff7cae41185b9c"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 24 34 30 33 61 64 63 37 61 2D 39 64 34 64 2D 34 64 37 39 2D 38 63 34 38 2D 36 36 31 61 64 63 66 66 37 33 65 35 }
    condition:
        all of them
}

rule Windows_Generic_Threat_06dcb833 {
    meta:
        author = "Elastic Security"
        id = "06dcb833-4aae-4be6-8433-5571841b7792"
        fingerprint = "3ff0bbf8d326661add9588aee99a2b5aac34fe719de7897aa84620c882d83095"
        creation_date = "2024-10-11"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "f7fde85aefb7123ef805c85394907ef73e0983499b49f2290a83aa2b0a2e5e9d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 8B EC 81 EC 04 36 00 00 B8 75 00 00 00 66 89 85 0C DA FF FF B9 73 00 00 00 66 89 8D 0E DA FF FF BA 65 00 00 00 66 89 95 10 DA FF FF B8 72 00 00 00 66 89 85 12 DA FF FF B9 33 00 00 00 66 89 }
    condition:
        all of them
}

rule Windows_Generic_Threat_5435fe36 {
    meta:
        author = "Elastic Security"
        id = "5435fe36-e581-4fbd-ba17-33e098c4ac9c"
        fingerprint = "b09215ef544d70233a2176589ec16159cabbb77da7a4232777eefe368fedc493"
        creation_date = "2024-10-11"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "8c0e26af4f9c783844ea457c3eb7bb2bbe1bf3f860ce180bacab00456f3ae7c1"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 83 EC 18 C7 45 F0 00 00 00 00 64 A1 30 00 00 00 89 45 EC C7 45 FC 00 00 00 00 8B 4D EC 8B 51 0C 8B 42 14 89 45 F4 8B 4D F4 89 4D F8 EB 08 8B 55 F8 8B 02 89 45 F8 8B 4D F4 8B 55 F8 3B }
    condition:
        all of them
}

rule Windows_Generic_Threat_491a8310 {
    meta:
        author = "Elastic Security"
        id = "491a8310-f42f-4069-a2ab-d65172055ba1"
        fingerprint = "5e4ec33a39f44925af4c7f743a04ae38f13cb3cbc6a0e55e9fcd777a1abd3122"
        creation_date = "2024-10-11"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "59c6846b4676378d9c80d7ced825f0463d1b333546bfcad919ee262cbf6db250"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 8B 45 0C 83 E8 02 74 21 2D 10 01 00 00 75 23 8B 45 14 50 8B 45 10 50 8B 45 0C 50 8B 45 08 50 ?? ?? ?? ?? ?? 89 45 FC EB 28 6A 00 ?? ?? ?? ?? ?? EB 1A 8B 45 14 50 8B 45 10 50 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2f726f2d {
    meta:
        author = "Elastic Security"
        id = "2f726f2d-4abe-47c9-9935-cd66e8c6b4cd"
        fingerprint = "2bda0cada0024df1d364d8c45bff7464e6deed015e989fcdff2a9e7baeab4192"
        creation_date = "2024-10-11"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ede9bd928a216c9844f290be0de6985ed54dceaff041906dca3a3468293464b6"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 83 EC 0C 89 4D F8 8B 45 F8 83 78 08 00 75 04 32 C0 EB 26 ?? ?? ?? ?? ?? ?? 89 4D F4 6A 00 8B 55 F8 8B 42 08 50 FF 55 F4 85 C0 74 06 C6 45 FF 01 EB 04 C6 45 FF 00 8A 45 FF 8B E5 5D C3 }
    condition:
        all of them
}

rule Windows_Generic_Threat_23ead7ed {
    meta:
        author = "Elastic Security"
        id = "23ead7ed-72d7-43d8-a840-7babf77b3a40"
        fingerprint = "14c76873b8b58c5bffd18790ae9c43170313766b55b725dc5ccd4abcf1e28d3a"
        creation_date = "2025-01-07"
        last_modified = "2025-05-27"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0bcd82ed4ea3e12cbaabc50df612d48078604e4d0985e9a240afc24630afa4d7"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 64 8B 0D 14 00 00 00 8B 89 00 00 00 00 3B 61 08 0F 86 6D 01 00 00 83 EC 18 8B 44 24 1C 89 04 24 0F B6 4C 24 20 0F B6 C9 89 4C 24 04 8B 4C 24 24 89 4C 24 08 8B 4C 24 28 89 4C 24 0C 8B 4C 24 2C }
    condition:
        all of them
}

rule Windows_Generic_Threat_3055c14a {
    meta:
        author = "Elastic Security"
        id = "3055c14a-3c32-4f42-8ea0-4a6add8174bc"
        fingerprint = "de7955235c4dac09ef5ae7228ef5cc8205c17e441132e77dee3697629d9824f0"
        creation_date = "2025-01-09"
        last_modified = "2025-05-27"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "69e0e00babc6365144a98c2866353ef973b7dfe69ae37068f807d4b12c017161"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 81 EC E0 00 00 00 48 8B F1 ?? ?? ?? ?? ?? ?? 48 63 F8 85 C0 75 11 48 8B B4 24 F8 00 00 00 48 81 C4 E0 00 00 00 5F C3 8D 47 01 48 89 9C 24 F0 00 00 00 48 63 C8 B8 02 00 00 00 48 F7 E1 }
    condition:
        all of them
}

