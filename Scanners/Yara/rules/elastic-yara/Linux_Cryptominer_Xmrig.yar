rule Linux_Cryptominer_Xmrig_57c0c6d7 {
    meta:
        author = "Elastic Security"
        id = "57c0c6d7-ded1-4a3e-9877-4003ab46d4a6"
        fingerprint = "b36ef33a052cdbda0db0048fc9da4ae4b4208c0fa944bc9322f029d4dfef35b8"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "100dc1ede4c0832a729d77725784d9deb358b3a768dfaf7ff9e96535f5b5a361"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 78 01 66 0F EF C9 49 89 38 0F BE 00 83 E8 30 F2 0F 2A C8 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_7e42bf80 {
    meta:
        author = "Elastic Security"
        id = "7e42bf80-60a4-4d45-bf07-b96a188c6e6b"
        fingerprint = "cf3b74ae6ff38b0131763fbcf65fa21fb6fd4462d2571b298c77a43184ac5415"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "551b6e6617fa3f438ec1b3bd558b3cbc981141904cab261c0ac082a697e5b07d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 70 F8 FF 66 0F 73 FD 04 66 44 0F EF ED 66 41 0F 73 FE 04 66 41 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_271121fb {
    meta:
        author = "Elastic Security"
        id = "271121fb-47cf-47a7-9e90-8565d4694c9e"
        fingerprint = "e0968731b0e006f3db92762822e4a3509d800e8f270b1c38303814fd672377a2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "19aeafb63430b5ac98e93dfd6469c20b9c1145e6b5b86202553bd7bd9e118842"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 18 41 C1 E4 10 C1 E1 08 41 C1 EA 10 44 89 CB 41 C1 E9 18 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_e7e64fb7 {
    meta:
        author = "Elastic Security"
        id = "e7e64fb7-e07c-4184-86bd-db491a2a11e0"
        fingerprint = "444240375f4b9c6948907c7e338764ac8221e5fcbbc2684bbd0a1102fef45e06"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 03 48 89 74 24 48 77 05 48 8B 5C C4 30 4C 8B 0A 48 8B 0F 48 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_77fbc695 {
    meta:
        author = "Elastic Security"
        id = "77fbc695-6fe3-4e30-bb2f-f64379ec4efd"
        fingerprint = "e0c6cb7a05c622aa40dfe2167099c496b714a3db4e9b92001bbe6928c3774c85"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "e723a2b976adddb01abb1101f2d3407b783067bec042a135b21b14d63bc18a68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F2 0F 58 44 24 08 F2 0F 11 44 24 08 8B 7B 08 41 8D 76 01 49 83 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_403b0a12 {
    meta:
        author = "Elastic Security"
        id = "403b0a12-8475-4e28-960b-ef33eabf0fcf"
        fingerprint = "785ac520b9f2fd9c6b49d8a485118eee7707f0fa0400b3db99eb7dfb1e14e350"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "54d806b3060404ccde80d9f3153eebe8fdda49b6e8cdba197df0659c6724a52d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 28 03 1C C3 0C 00 C0 00 60 83 1C A7 71 00 00 00 68 83 5C D7 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_bffa106b {
    meta:
        author = "Elastic Security"
        id = "bffa106b-0a9a-4433-b9ac-ae41a020e7e0"
        fingerprint = "665b5684c55c88e55bcdb8761305d6428c6a8e810043bf9df0ba567faea4c435"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 24 9C 44 0F B6 94 24 BC 00 00 00 89 5C 24 A0 46 8B 0C 8A 66 0F 6E 5C }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_73faf972 {
    meta:
        author = "Elastic Security"
        id = "73faf972-43e4-448d-bdfd-cda9be15fce6"
        fingerprint = "f31c2658acd6d13ae000426d3845bcec7a8a587bbaed75173baa84b2871b0b42"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "00e29303b66cb39a8bc23fe91379c087376ea26baa21f6b7f7817289ba89f655"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6F C4 83 E0 01 83 E1 06 09 C1 44 89 E8 01 C9 D3 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_af809eea {
    meta:
        author = "Elastic Security"
        id = "af809eea-fe42-4495-b7e5-c22b39102fcd"
        fingerprint = "373d2f57aede0b41296011d12b59ac006f6cf0e2bd95163f518e6e252459411b"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "00e29303b66cb39a8bc23fe91379c087376ea26baa21f6b7f7817289ba89f655"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 E0 01 83 E1 06 09 C1 44 89 ?? 01 C9 D3 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_9f6ac00f {
    meta:
        author = "Elastic Security"
        id = "9f6ac00f-1562-4be1-8b54-bf9a89672b0e"
        fingerprint = "77b171a3099327a5edb59b8f1b17fb3f415ab7fd15beabcd3b53916cde206568"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "9cd58c1759056c0c5bbd78248b9192c4f8c568ed89894aff3724fdb2be44ca43"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B8 31 75 00 00 83 E3 06 09 D9 01 C9 D3 F8 89 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_dbcc9d87 {
    meta:
        author = "Elastic Security"
        id = "dbcc9d87-5064-446d-9581-b14cf183ec3f"
        fingerprint = "ebb6d184d7470437aace81d55ada5083e55c0de67e566b052245665aeda96d69"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "da9b8fb5c26e81fb3aed3b0bc95d855339fced303aae2af281daf0f1a873e585"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 78 72 47 47 58 34 53 58 5F 34 74 43 41 66 30 5A 57 73 00 64 48 8B 0C 25 F8 FF }
    condition:
        all of them
}

