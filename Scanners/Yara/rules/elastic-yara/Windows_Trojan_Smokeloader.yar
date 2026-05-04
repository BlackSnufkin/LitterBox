rule Windows_Trojan_Smokeloader_4e31426e {
    meta:
        author = "Elastic Security"
        id = "4e31426e-d62e-4b6d-911b-4223e1f6adef"
        fingerprint = "cf6d8615643198bc53527cb9581e217f8a39760c2e695980f808269ebe791277"
        creation_date = "2021-07-21"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "1ce643981821b185b8ad73b798ab5c71c6c40e1f547b8e5b19afdaa4ca2a5174"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 5B 81 EB 34 10 00 00 6A 30 58 64 8B 00 8B 40 0C 8B 40 1C 8B 40 08 89 85 C0 }
    condition:
        all of them
}

rule Windows_Trojan_Smokeloader_4ee15b92 {
    meta:
        author = "Elastic Security"
        id = "4ee15b92-c62f-42d2-bbba-1dac2fa5644f"
        fingerprint = "5d2ed385c76dbb4c1c755ae88b68306086a199a25a29317ae132bc874b253580"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "09b9283286463b35ea2d5abfa869110eb124eb8c1788eb2630480d058e82abf2"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 24 34 30 33 33 8B 45 F4 5F 5E 5B C9 C2 10 00 55 89 E5 83 EC }
    condition:
        all of them
}

rule Windows_Trojan_Smokeloader_ea14b2a5 {
    meta:
        author = "Elastic Security"
        id = "ea14b2a5-ea0d-4da2-8190-dbfcda7330d9"
        fingerprint = "950ce9826fdff209b6e03c70a4f78b812d211a2a9de84bec0e5efe336323001b"
        creation_date = "2023-05-03"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "15fe237276b9c2c6ceae405c0739479d165b406321891c8a31883023e7b15d54"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { AC 41 80 01 AC 41 80 00 AC 41 80 00 AC 41 C0 00 AC 41 80 01 }
        $a2 = { AC 41 80 00 AC 41 80 07 AC 41 80 00 AC 41 80 00 AC 41 80 00 }
    condition:
        all of them
}

rule Windows_Trojan_Smokeloader_de52ed44 {
    meta:
        author = "Elastic Security"
        id = "de52ed44-062c-4b0d-9a41-1bfc31a8daa9"
        fingerprint = "950db8f87a81ef05cc2ecbfa174432ab31a3060c464836f3b38448bd8e5801be"
        creation_date = "2023-05-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "c689a384f626616005d37a94e6a5a713b9eead1b819a238e4e586452871f6718"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 08 31 FF 89 7D CC 66 8C E8 66 85 C0 74 03 FF 45 CC FF 53 48 }
        $a2 = { B0 8F 45 C8 8D 45 B8 89 38 8D 4D C8 6A 04 57 6A 01 51 57 57 }
    condition:
        all of them
}

rule Windows_Trojan_Smokeloader_bf391fe0 {
    meta:
        author = "Elastic Security"
        id = "bf391fe0-7e7f-4f29-8a8c-c13aa2c1eef1"
        fingerprint = "513355978aca1f1dd21c199c7fbf72a59639ad08d0c8712d7d076a67da737ab5"
        creation_date = "2024-08-27"
        last_modified = "2024-09-30"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "fe2489230d024f5e0e7d0da0210f93e70248dc282192c092cbb5e0eddc7bd528"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8A 54 3C 18 0F B6 C2 03 F0 23 F1 8A 44 34 18 88 44 3C 18 88 54 34 18 0F B6 4C 3C 18 }
        $b = { 8D 87 77 05 00 00 50 8B 44 24 18 05 36 01 00 00 50 }
    condition:
        any of them
}

rule Windows_Trojan_Smokeloader_a01aa3ab {
    meta:
        author = "Elastic Security"
        id = "a01aa3ab-b1d8-4cd1-8349-ff105e285f5d"
        fingerprint = "75b4fd2ace9aa87dab9fef950171a566bed8355ae4f7076755fa5293c68936a6"
        creation_date = "2024-08-27"
        last_modified = "2024-09-30"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "3a189a736cfdfbb1e3789326c35cecfa901a2adccc08c66c5de1cac8e4c1791b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 83 A6 43 0C 00 00 00 83 A6 3F 0C 00 00 00 45 33 C9 45 8D 41 04 33 D2 33 C9 }
        $b = { 42 0F B6 14 0C 41 8D 04 12 44 0F B6 D0 42 8A 04 14 42 88 04 0C 42 88 14 14 42 0F B6 }
    condition:
        any of them
}

rule Windows_Trojan_Smokeloader_62eb5427 {
    meta:
        author = "Elastic Security"
        id = "62eb5427-0488-4c6c-aefc-00f4120bd2a9"
        fingerprint = "eb9b8149997deb5701c51d6cac58e03a111c23cba2cc1bb4abcfaa56f201cc08"
        creation_date = "2024-08-27"
        last_modified = "2024-09-30"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "21e7fcce8ffb7826108800b6aee21d6b8ea9275975b639ed5ca9f8ddd747329e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { C7 45 FC 00 00 00 00 8B 45 08 03 40 3C 8B 40 78 03 45 08 50 8B 48 18 8B 50 20 03 55 08 }
        $b = { 8B 7D F4 89 F1 B8 19 04 00 00 F2 66 AF }
        $c = { C7 44 05 D0 53 6C 65 65 8B 45 C8 83 C0 04 89 45 C8 }
    condition:
        any of them
}

