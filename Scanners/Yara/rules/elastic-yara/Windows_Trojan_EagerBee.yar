rule Windows_Trojan_EagerBee_7029ba21 {
    meta:
        author = "Elastic Security"
        id = "7029ba21-12ea-4120-911b-a36c4002409e"
        fingerprint = "26d0d10f7c503e284e2b24a9e273f880d2e152348dfdd44fb3fc8cb10aa57e2a"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.EagerBee"
        reference = "https://www.elastic.co/security-labs/introducing-the-ref5961-intrusion-set"
        reference_sample = "09005775fc587ac7bf150c05352e59dc01008b7bf8c1d870d1cea87561aa0b06"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { C2 EB D6 0F B7 C2 48 8D 0C 80 41 8B 44 CB 14 41 2B 44 CB 0C 41 }
        $a2 = { C8 75 04 33 C0 EB 7C 48 63 41 3C 8B 94 08 88 00 00 00 48 03 D1 8B }
    condition:
        all of them
}

rule Windows_Trojan_EagerBee_a64b323b {
    meta:
        author = "Elastic Security"
        id = "a64b323b-60b6-49b9-99d2-82a336fe304e"
        fingerprint = "5109ec213a2ac1a1d920f3a9753bed97d038b226775996002511df5dc0b6de9c"
        creation_date = "2023-09-04"
        last_modified = "2023-09-20"
        threat_name = "Windows.Trojan.EagerBee"
        reference = "https://www.elastic.co/security-labs/introducing-the-ref5961-intrusion-set"
        reference_sample = "339e4fdbccb65b0b06a1421c719300a8da844789a2016d58e8ce4227cb5dc91b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $dexor_config_file = { 48 FF C0 8D 51 FF 44 30 00 49 03 C4 49 2B D4 ?? ?? 48 8D 4F 01 48 }
        $parse_config = { 80 7C 14 20 3A ?? ?? ?? ?? ?? ?? 45 03 C4 49 03 D4 49 63 C0 48 3B C1 }
        $parse_proxy1 = { 44 88 7C 24 31 44 88 7C 24 32 48 F7 D1 C6 44 24 33 70 C6 44 24 34 3D 88 5C 24 35 48 83 F9 01 }
        $parse_proxy2 = { 33 C0 48 8D BC 24 F0 00 00 00 49 8B CE F2 AE 8B D3 48 F7 D1 48 83 E9 01 48 8B F9 }
    condition:
        2 of them
}

