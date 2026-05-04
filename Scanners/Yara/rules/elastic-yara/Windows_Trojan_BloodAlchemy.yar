rule Windows_Trojan_BloodAlchemy_3793364e {
    meta:
        author = "Elastic Security"
        id = "3793364e-a73c-4cf0-855c-fdcdb2b88386"
        fingerprint = "b4620f360093284ae6f2296b4239227099f58f8f0cfe9f70298c84d6cbe7fa29"
        creation_date = "2023-09-25"
        last_modified = "2023-09-25"
        threat_name = "Windows.Trojan.BloodAlchemy"
        reference = "https://www.elastic.co/security-labs/disclosing-the-bloodalchemy-backdoor"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 83 65 FC 00 53 56 57 BF 00 20 00 00 57 6A 40 FF 15 }
        $a2 = { 55 8B EC 81 EC 80 00 00 00 53 56 57 33 FF 8D 45 80 6A 64 57 50 89 7D E4 89 7D EC 89 7D F0 89 7D }
    condition:
        all of them
}

rule Windows_Trojan_BloodAlchemy_e510798d {
    meta:
        author = "Elastic Security"
        id = "e510798d-a938-47ba-92e3-0c1bcd3ce9a9"
        fingerprint = "151519156e4c6b5395c03f70c77601681f17f86a08db96a622b9489a3df682d6"
        creation_date = "2023-09-25"
        last_modified = "2023-09-25"
        threat_name = "Windows.Trojan.BloodAlchemy"
        reference = "https://www.elastic.co/security-labs/disclosing-the-bloodalchemy-backdoor"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 83 EC 54 53 8B 5D 08 56 57 33 FF 89 55 F4 89 4D F0 BE 00 00 00 02 89 7D F8 89 7D FC 85 DB }
        $a2 = { 55 8B EC 83 EC 0C 56 57 33 C0 8D 7D F4 AB 8D 4D F4 AB AB E8 42 10 00 00 8B 7D F4 33 F6 85 FF 74 03 8B 77 08 }
    condition:
        any of them
}

rule Windows_Trojan_BloodAlchemy_63084eea {
    meta:
        author = "Elastic Security"
        id = "63084eea-358b-4fb0-9668-3f40f0aae9e7"
        fingerprint = "3f6ef0425b846b2126263c590d984bc618ad61de91a9141160c2b804c585ff6d"
        creation_date = "2023-09-25"
        last_modified = "2023-09-25"
        threat_name = "Windows.Trojan.BloodAlchemy"
        reference = "https://www.elastic.co/security-labs/disclosing-the-bloodalchemy-backdoor"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 8B EC 83 EC 38 53 56 57 8B 75 08 8D 7D F0 33 C0 33 DB AB 89 5D C8 89 5D D0 89 5D D4 AB 89 5D }
    condition:
        all of them
}

rule Windows_Trojan_BloodAlchemy_c2d80609 {
    meta:
        author = "Elastic Security"
        id = "c2d80609-9a66-4fbb-b594-17d16372cb14"
        fingerprint = "8815e42ef85ae5a8915cd26b573cd7411c041778cdf4bc99efd45526e3699642"
        creation_date = "2023-09-25"
        last_modified = "2023-09-25"
        threat_name = "Windows.Trojan.BloodAlchemy"
        reference = "https://www.elastic.co/security-labs/disclosing-the-bloodalchemy-backdoor"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 8B EC 83 EC 30 53 56 57 33 C0 8D 7D F0 AB 33 DB 68 02 80 00 00 6A 40 89 5D FC AB AB FF 15 28 }
    condition:
        all of them
}

rule Windows_Trojan_BloodAlchemy_de591c5a {
    meta:
        author = "Elastic Security"
        id = "de591c5a-95a5-4a23-bc02-7bc487b6ca4b"
        fingerprint = "6765378490707c5965dc4abd04169d4a94b787be3fccf3b77f1eff5d507090a4"
        creation_date = "2023-09-25"
        last_modified = "2023-11-02"
        threat_name = "Windows.Trojan.BloodAlchemy"
        reference = "https://www.elastic.co/security-labs/disclosing-the-bloodalchemy-backdoor"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $crypto_0 = { 32 C7 8A DF 88 04 39 8B C1 6A 05 59 F7 F1 8A C7 8D 4A 01 D2 E3 B1 07 2A CA D2 E8 8B 4D F8 0A D8 02 FB 41 }
        $crypto_1 = { 8A 1F 0F B6 C3 83 E0 7F D3 E0 99 09 55 ?? 0B F0 47 84 DB 79 ?? 83 C1 07 83 F9 3F }
        $crypto_2 = { E8 [4] 03 F0 33 D2 8B C6 89 75 ?? 25 FF FF FF 7F 6A 34 59 F7 F1 8B 45 ?? 66 8B 0C 55 [4] 66 89 0C 43 40 89 45 ?? 3B C7 }
        $crypto_3 = { 61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6A 00 6B 00 6C 00 6D 00 6E 00 6F 00 70 00 71 00 72 00 73 00 74 00 }
        $com_tm_cid = { 9F 36 87 0F E5 A4 FC 4C BD 3E 73 E6 15 45 72 DD }
        $com_tm_iid = { C0 C7 A4 AB 2F A9 4D 13 40 96 97 20 CC 3F D4 0F 85 }
    condition:
        any of ($crypto_*) and all of ($com_tm_*)
}

