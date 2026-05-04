rule Windows_Trojan_Emotet_18379a8d {
    meta:
        author = "Elastic Security"
        id = "18379a8d-f1f2-49cc-8edf-58a3ba77efe7"
        fingerprint = "b7650b902a1a02029e28c88dd7ff91d841136005b0246ef4a08aaf70e57df9cc"
        creation_date = "2021-11-17"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Emotet"
        reference = "https://www.elastic.co/security-labs/emotet-dynamic-configuration-extraction"
        reference_sample = "eeb13cd51faa7c23d9a40241d03beb239626fbf3efe1dbbfa3994fc10dea0827"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 04 33 CB 88 0A 8B C1 C1 E8 08 8D 52 04 C1 E9 10 88 42 FD 88 }
    condition:
        all of them
}

rule Windows_Trojan_Emotet_5528b3b0 {
    meta:
        author = "Elastic Security"
        id = "5528b3b0-d4cb-485e-bc0c-96415ec3a795"
        fingerprint = "717ed656d1bd4ba0e4dae8e47268e2c068dad3e3e883ff6da2f951d61f1be642"
        creation_date = "2021-11-17"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Emotet"
        reference = "https://www.elastic.co/security-labs/emotet-dynamic-configuration-extraction"
        reference_sample = "eeb13cd51faa7c23d9a40241d03beb239626fbf3efe1dbbfa3994fc10dea0827"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 20 89 44 24 10 83 C2 02 01 74 24 10 01 7C 24 10 29 5C 24 10 66 }
    condition:
        all of them
}

rule Windows_Trojan_Emotet_1943bbf2 {
    meta:
        author = "Elastic Security"
        id = "1943bbf2-56c0-443e-9208-cd8fc3b02d79"
        fingerprint = "df8b73d83a50a58ed8332b7580c970c2994aa31d2ac1756cff8e0cd1777fb8fa"
        creation_date = "2021-11-18"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Emotet"
        reference = "https://www.elastic.co/security-labs/emotet-dynamic-configuration-extraction"
        reference_sample = "5abec3cd6aa066b1ddc0149a911645049ea1da66b656c563f9a384e821c5db38"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 66 83 38 5C 74 0A 83 C0 02 66 39 30 75 F2 EB 06 33 C9 66 89 }
    condition:
        all of them
}

rule Windows_Trojan_Emotet_db7d33fa {
    meta:
        author = "Elastic Security"
        id = "db7d33fa-e50c-4c59-ab92-edb74aac87c9"
        fingerprint = "eac196154ab1ad636654c966e860dcd5763c50d7b8221dbbc7769c879daf02fd"
        creation_date = "2022-05-09"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.Emotet"
        reference = "https://www.elastic.co/security-labs/emotet-dynamic-configuration-extraction"
        reference_sample = "08c23400ff546db41f9ddbbb19fa75519826744dde3b3afb38f3985266577afc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $chunk_0 = { 4C 8D 9C 24 ?? ?? ?? ?? 8B C3 49 8B 5B ?? 49 8B 73 ?? 49 8B 7B ?? 49 8B E3 5D C3 }
        $chunk_1 = { 8B C7 41 0F B7 4C 45 ?? 41 8B 1C 8C 48 03 DD 48 3B DE 72 ?? }
        $chunk_2 = { 48 8B C4 48 89 48 ?? 48 89 50 ?? 4C 89 40 ?? 4C 89 48 ?? C3 }
        $chunk_3 = { 48 8B 45 ?? BB 01 00 00 00 48 89 07 8B 45 ?? 89 47 ?? 4C 8D 9C 24 ?? ?? ?? ?? 8B C3 49 8B 5B ?? 49 8B 73 ?? 49 8B 7B ?? 49 8B E3 5D C3 }
        $chunk_4 = { 48 39 3B 4C 8D 9C 24 ?? ?? ?? ?? 49 8B 5B ?? 49 8B 73 ?? 40 0F 95 C7 8B C7 49 8B 7B ?? 49 8B E3 5D C3 }
        $chunk_5 = { BE 02 00 00 00 4C 8D 9C 24 ?? ?? ?? ?? 8B C6 49 8B 5B ?? 49 8B 73 ?? 49 8B 7B ?? 49 8B E3 41 5F 41 5E 41 5D 41 5C 5D C3 }
        $chunk_6 = { 43 8B 84 FE ?? ?? ?? ?? 48 03 C6 48 3B D8 73 ?? }
        $chunk_7 = { 88 02 48 FF C2 48 FF C3 8A 03 84 C0 75 ?? EB ?? }
    condition:
        4 of them
}

rule Windows_Trojan_Emotet_d6ac1ea4 {
    meta:
        author = "Elastic Security"
        id = "d6ac1ea4-b0a8-4023-b712-9f4f2c7146a3"
        fingerprint = "7e6224c58c283765b5e819eb46814c556ae6b7b5931cd1e3e19ca3ec8fa31aa2"
        creation_date = "2022-05-24"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.Emotet"
        reference = "https://www.elastic.co/security-labs/emotet-dynamic-configuration-extraction"
        reference_sample = "2c6709d5d2e891d1ce26fdb4021599ac10fea93c7773f5c00bea8e5e90404b71"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $calc1 = { C7 44 24 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? }
        $pre = { 48 83 EC ( 18 | 28 ) C7 44 24 ?? ?? ?? ?? ?? }
        $setup = { 48 8D 05 ?? ?? ?? ?? 48 89 81 ?? ?? ?? ?? }
        $post = { 8B 44 24 ?? 89 44 24 ?? 48 83 C4 18 C3 }
    condition:
        #calc1 >= 10 and #pre >= 5 and #setup >= 5 and #post >= 5
}

rule Windows_Trojan_Emotet_77c667b9 {
    meta:
        author = "Elastic Security"
        id = "77c667b9-6895-428f-8735-ba5853d9484d"
        fingerprint = "f8fac966f77cd8d6654b8abffbf63d884bd9f0b5d51bfc252004a0d9bd569068"
        creation_date = "2022-11-07"
        last_modified = "2022-12-20"
        threat_name = "Windows.Trojan.Emotet"
        reference = "https://www.elastic.co/security-labs/emotet-dynamic-configuration-extraction"
        reference_sample = "ffac0120c3ae022b807559e8ed7902fde0fa5f7cb9c5c8d612754fa498288572"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $c2_list_1 = { 8B 4B ?? 8B 85 ?? ?? ?? ?? 48 FF C1 48 C1 E1 ?? 89 04 19 8B 43 ?? 8B 8D ?? ?? ?? ?? 48 C1 E0 ?? C1 E9 ?? 66 89 4C 18 ?? }
        $c2_list_2 = { 8B 43 ?? 48 8D 0C 80 8B 44 24 ?? 89 44 CB ?? 8B 43 ?? 8B 54 24 ?? 48 8D 0C 80 C1 EA ?? 66 89 54 CB ?? 8B 43 ?? 0F B7 54 24 ?? 48 8D 0C 80 89 54 CB ?? FF 43 ?? }
        $c2_list_3 = { 8B 43 ?? 48 FF C0 48 8D 0C 40 8B 85 ?? ?? ?? ?? 48 03 C9 89 04 CB 8B 43 ?? 8B 95 ?? ?? ?? ?? 48 8D 0C 40 C1 EA ?? 48 03 C9 66 89 54 CB ?? 8B 43 ?? 0F B7 95 ?? ?? ?? ?? 48 8D 0C 40 B8 ?? ?? ?? ?? 48 03 C9 89 54 CB ?? FF 43 ?? }
        $c2_list_4 = { 8B 43 ?? 48 FF C0 48 8D 0C 40 8B 44 24 ?? 89 04 CB 8B 43 ?? 8B 54 24 ?? 48 8D 0C 40 C1 EA ?? 66 89 54 CB ?? 8B 43 ?? 0F B7 54 24 ?? 48 8D 0C 40 89 54 CB ?? FF 43 ?? }
        $c2_list_5 = { 8B 83 ?? ?? ?? ?? 48 8D 0C 80 8B 44 24 ?? 89 44 CB ?? 8B 83 ?? ?? ?? ?? 8B 54 24 ?? 48 8D 0C 80 C1 EA ?? 66 89 54 CB ?? 8B 83 ?? ?? ?? ?? 0F B7 54 24 ?? 48 8D 0C 80 89 14 CB FF 83 ?? ?? ?? ?? }
        $c2_list_a = { 8B 83 ?? ?? ?? ?? 83 F8 ?? 73 ?? 48 8D 4C 24 ?? FF 54 C4 ?? 83 7C 24 ?? ?? 74 ?? 83 7C 24 ?? ?? 74 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
        $string_w_1 = { 8B 0B 49 FF C3 48 8D 5B ?? 33 CD 0F B6 C1 66 41 89 00 0F B7 C1 C1 E9 ?? 66 C1 E8 ?? 4D 8D 40 ?? 66 41 89 40 ?? 0F B6 C1 66 C1 E9 ?? 66 41 89 40 ?? 66 41 89 48 ?? 4D 3B D9 72 ?? }
        $string_w_2 = { 8B CD 49 FF C3 33 0B 48 8D 5B ?? 0F B6 C1 66 41 89 00 0F B7 C1 C1 E9 ?? 66 C1 E8 ?? 4D 8D 40 ?? 66 41 89 40 ?? 0F B6 C1 66 C1 E9 ?? 66 41 89 40 ?? 66 41 89 48 ?? 4D 3B D9 72 ?? }
        $string_a_1 = { 8B 0B 49 FF C3 48 8D 5B ?? 33 CD 41 88 08 0F B7 C1 C1 E9 ?? 66 C1 E8 ?? 4D 8D 40 ?? 41 88 40 ?? 41 88 48 ?? 66 C1 E9 ?? 41 88 48 ?? 4D 3B D9 72 ?? }
        $key_1 = { 45 33 C9 4C 8B D0 48 85 C0 74 ?? 48 8D ?? ?? 4C 8B ?? 48 8B ?? 48 2B ?? 48 83 ?? ?? 48 C1 ?? ?? 48 3B ?? 49 0F 47 ?? 48 85 ?? 74 ?? 48 2B D8 42 8B 04 03 }
    condition:
        (1 of ($string_*)) and (($key_1 or (1 of ($c2_list*))) or (1 of ($c2_list*)))
}

rule Windows_Trojan_Emotet_8b9449c1 {
    meta:
        author = "Elastic Security"
        id = "8b9449c1-41a3-4f4d-b654-6921f2742b9a"
        fingerprint = "ff15cec5eb41bb9637b570d717151cdc076e88a7b4c3d1c31157d41fe7569318"
        creation_date = "2022-11-09"
        last_modified = "2022-12-20"
        threat_name = "Windows.Trojan.Emotet"
        reference = "https://www.elastic.co/security-labs/emotet-dynamic-configuration-extraction"
        reference_sample = "ffac0120c3ae022b807559e8ed7902fde0fa5f7cb9c5c8d612754fa498288572"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $hash_1 = { 8B CB 41 8B D0 D3 E2 41 8B CB D3 E0 03 D0 41 0F BE ?? 03 D0 41 2B D0 49 FF ( C1 | C2 ) }
        $hash_2 = { 44 8B ?? 44 8B ?? 41 8B CB 41 D3 ?? 8B CB D3 E0 8B C8 8D 42 ?? 66 83 F8 ?? 0F B7 C2 77 ?? 83 C0 ?? 41 2B ?? 41 03 ?? 03 C1 49 83 ?? ?? 41 0F B7 }
    condition:
        any of them
}

