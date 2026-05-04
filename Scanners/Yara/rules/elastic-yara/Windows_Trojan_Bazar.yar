rule Windows_Trojan_Bazar_711d59f6 {
    meta:
        author = "Elastic Security"
        id = "711d59f6-6e8a-485d-b362-4c1bf1bda66e"
        fingerprint = "a9e78b4e39f4acaba86c2595db67fcdcd40d1af611d41a023bd5d8ca9804efa4"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Bazar"
        reference_sample = "f29253139dab900b763ef436931213387dc92e860b9d3abb7dcd46040ac28a0e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 0F 94 C3 41 0F 95 C0 83 FA 0A 0F 9C C1 83 FA 09 0F 9F C2 31 C0 }
    condition:
        all of them
}

rule Windows_Trojan_Bazar_9dddea36 {
    meta:
        author = "Elastic Security"
        id = "9dddea36-1345-434b-8ce6-54d2eab39616"
        fingerprint = "e322e36006cc017d5d5d9887c89b180c5070dbe5a9efd9fb7ae15cda5b726d6c"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Bazar"
        reference_sample = "63df43daa61f9a0fbea2e5409b8f0063f7af3363b6bc8d6984ce7e90c264727d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { C4 10 5B 5F 5E C3 41 56 56 57 55 53 48 83 EC 18 48 89 C8 48 }
    condition:
        all of them
}

rule Windows_Trojan_Bazar_3a2cc53b {
    meta:
        author = "Elastic Security"
        id = "3a2cc53b-4f73-41f9-aabd-08b8755ba44c"
        fingerprint = "f146d4fff29011acf595f2cba10ed7c3ce6ba07fbda0864d746f8e6355f91add"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Bazar"
        reference_sample = "b057eb94e711995fd5fd6c57aa38a243575521b11b98734359658a7a9829b417"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 63 41 3C 45 33 ED 44 8B FA 48 8B F9 8B 9C 08 88 00 00 00 44 8B A4 08 8C 00 }
    condition:
        all of them
}

rule Windows_Trojan_Bazar_de8d625a {
    meta:
        author = "Elastic Security"
        id = "de8d625a-8f85-47b7-bcad-e3cc012e4654"
        fingerprint = "17b2de5803589634fd7fb4643730fbebfa037c4d0b66be838a1c78af22da0228"
        creation_date = "2022-01-14"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Bazar"
        reference_sample = "1ad9ac4785b82c8bfa355c7343b9afc7b1f163471c41671ea2f9152a1b550f0c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F0 48 8B FA 48 8B D9 48 85 D2 74 61 4D 85 C0 74 5C 48 39 11 75 06 4C 39 41 08 74 2B 48 8B 49 }
    condition:
        all of them
}

