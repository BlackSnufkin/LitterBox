rule Windows_Trojan_SpectralViper_43abeeeb {
    meta:
        author = "Elastic Security"
        id = "43abeeeb-d81a-475e-9b9e-6b6337bf2ce0"
        fingerprint = "0e19e57e936d08f68c5580d21c2d69d451cfc11d413c6125dbdaab863b73d5c7"
        creation_date = "2023-04-13"
        last_modified = "2023-05-26"
        threat_name = "Windows.Trojan.SpectralViper"
        reference = "https://www.elastic.co/security-labs/elastic-charms-spectralviper"
        reference_sample = "7e35ba39c2c77775b0394712f89679308d1a4577b6e5d0387835ac6c06e556cb"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 13 00 8D 58 FF 0F AF D8 F6 C3 01 0F 94 44 24 26 83 FD 0A 0F 9C 44 24 27 4D 89 CE 4C 89 C7 48 89 D3 48 89 CE B8 }
        $a2 = { 15 00 8D 58 FF 0F AF D8 F6 C3 01 0F 94 44 24 2E 83 FD 0A 0F 9C 44 24 2F 4D 89 CE 4C 89 C7 48 89 D3 48 89 CE B8 }
        $a3 = { 00 8D 68 FF 0F AF E8 40 F6 C5 01 0F 94 44 24 2E 83 FA 0A 0F 9C 44 24 2F 4C 89 CE 4C 89 C7 48 89 CB B8 }
        $a4 = { 00 48 89 C6 0F 29 30 0F 29 70 10 0F 29 70 20 0F 29 70 30 0F 29 70 40 0F 29 70 50 48 C7 40 60 00 00 00 00 48 89 C1 E8 }
        $a5 = { 41 0F 45 C0 45 84 C9 41 0F 45 C0 EB BA 48 89 4C 24 08 89 D0 EB B1 48 8B 44 24 08 48 83 C4 10 C3 56 57 53 48 83 EC 30 8B 05 }
        $a6 = { 00 8D 70 FF 0F AF F0 40 F6 C6 01 0F 94 44 24 25 83 FF 0A 0F 9C 44 24 26 89 D3 48 89 CF 48 }
        $a7 = { 48 89 CE 48 89 11 4C 89 41 08 41 0F 10 01 41 0F 10 49 10 41 0F 10 51 20 0F 11 41 10 0F 11 49 20 0F 11 51 30 }
        $a8 = { 00 8D 58 FF 0F AF D8 F6 C3 01 0F 94 44 24 22 83 FD 0A 0F 9C 44 24 23 48 89 D6 48 89 CF 4C 8D }
    condition:
        5 of them
}

rule Windows_Trojan_SpectralViper_368c36a0 {
    meta:
        author = "Elastic Security"
        id = "368c36a0-d8ec-4cd6-92b3-193907898dc1"
        fingerprint = "cfe4df5390a625d59f1c30775fe26119707a296feb1a205f3df734a4c0fcc25c"
        creation_date = "2023-05-10"
        last_modified = "2023-05-10"
        threat_name = "Windows.Trojan.SpectralViper"
        reference = "https://www.elastic.co/security-labs/elastic-charms-spectralviper"
        reference_sample = "d1c32176b46ce171dbce46493eb3c5312db134b0a3cfa266071555c704e6cff8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 18 48 89 4F D8 0F 10 40 20 0F 11 47 E0 0F 10 40 30 0F 11 47 F0 48 8D }
        $a2 = { 24 27 48 83 C4 28 5B 5D 5F 5E C3 56 57 53 48 83 EC 20 48 89 CE 48 }
        $a3 = { C7 84 C9 0F 45 C7 EB 86 48 8B 44 24 28 48 83 C4 30 5B 5F 5E C3 48 83 }
        $s1 = { 40 53 48 83 EC 20 48 8B 01 48 8B D9 48 8B 51 10 48 8B 49 08 FF D0 48 89 43 18 B8 04 00 00 }
        $s2 = { 40 53 48 83 EC 20 48 8B 01 48 8B D9 48 8B 49 08 FF D0 48 89 43 10 B8 04 00 00 00 48 83 C4 20 5B }
        $s3 = { 48 83 EC 28 4C 8B 41 18 4C 8B C9 48 B8 AB AA AA AA AA AA AA AA 48 F7 61 10 48 8B 49 08 48 C1 EA }
    condition:
        2 of ($a*) or any of ($s*)
}

