rule Windows_Trojan_Zloader_5dd0a0bf {
    meta:
        author = "Elastic Security"
        id = "5dd0a0bf-20e4-4c52-b9d9-c157e871b06b"
        fingerprint = "06545df6c556adf8a6844724e77d005c0299b544f21df2ea44bb9679964dbb9f"
        creation_date = "2022-03-03"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Zloader"
        reference_sample = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { B6 08 89 CA 80 C2 F7 80 FA 05 72 F2 80 F9 20 74 ED 03 5D 0C 8D }
    condition:
        all of them
}

rule Windows_Trojan_Zloader_4fe0f7f1 {
    meta:
        author = "Elastic Security"
        id = "4fe0f7f1-93c6-4397-acd5-1557608efaf4"
        fingerprint = "f340f41cc69930d24ffdae484d1080cd9ce5cb5e7720868c956923a5b8e6c9b1"
        creation_date = "2022-03-03"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Zloader"
        reference_sample = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 08 8B 75 F0 85 DB 8D 7D 94 89 45 E8 0F 45 FB 31 DB 85 F6 0F }
    condition:
        all of them
}

rule Windows_Trojan_Zloader_363c65ed {
    meta:
        author = "Elastic Security"
        id = "363c65ed-e394-4a40-9c2a-a6f6fd284ed3"
        fingerprint = "33ae4cee122269f4342a3fd829236cbd303d8821b548ab93bbebc9dee3eb67f2"
        creation_date = "2022-03-03"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Zloader"
        reference_sample = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 04 8D 4D E4 8D 55 E8 6A 00 6A 00 51 6A 00 6A 00 50 52 57 53 }
    condition:
        all of them
}

rule Windows_Trojan_Zloader_79535191 {
    meta:
        author = "Elastic Security"
        id = "79535191-59df-4c78-9f62-b8614ef992d3"
        fingerprint = "ee3c4cf0d694119acfdc945a964e4fc0f51355eabca900ffbcc21aec0b3e1e3c"
        creation_date = "2022-03-03"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Zloader"
        reference_sample = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 28 4B 74 26 8B 46 FC 85 C0 74 F3 8B 4E F4 8B 16 39 C8 0F 47 C1 8B }
    condition:
        all of them
}

