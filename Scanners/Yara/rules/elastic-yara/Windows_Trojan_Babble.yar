rule Windows_Trojan_Babble_0d6c9505 {
    meta:
        author = "Elastic Security"
        id = "0d6c9505-6551-42e9-98e9-3a5c66878fc7"
        fingerprint = "d2638ad071c7b8f80be137b88bd3bf878b0eb64f920cf41bd44f9da16cf0f83f"
        creation_date = "2024-11-18"
        last_modified = "2024-11-26"
        threat_name = "Windows.Trojan.Babble"
        reference_sample = "fa292bfcf81223bab0f79d4ce08187e37d68960005629df0241ea22f0b95d7a8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 24 48 0F B7 04 48 48 8B 4C 24 78 48 8B 09 8B 04 81 48 8B 4C 24 78 48 03 41 20 48 89 44 24 28 48 }
        $a2 = { 44 24 34 C1 E0 08 0F B6 4C 24 35 0F B7 54 24 20 03 CA 0B C1 48 8B 8C 24 80 00 00 00 89 01 EB 05 }
    condition:
        all of them
}

