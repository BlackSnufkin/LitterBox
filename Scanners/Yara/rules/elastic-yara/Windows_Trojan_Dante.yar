rule Windows_Trojan_Dante_0d708df5 {
    meta:
        author = "Elastic Security"
        id = "0d708df5-a4a0-49ac-98aa-0b282c4d98fa"
        fingerprint = "dea58a546de3753303240455958e115e5c22a7ee7ce72f61c1cddf7f69ee1d49"
        creation_date = "2025-11-01"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Dante"
        reference_sample = "f5cd047e319433e92995c92bb7fc9bf3c28a63060339060f325d4b8894b55b48"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 83 C3 20 48 3B DF ?? ?? 48 8B 7D D8 48 8B 5D D0 41 8B F6 48 8B 4D E8 48 3B 4D F0 40 0F 95 C6 48 85 DB ?? ?? 48 8B D7 48 8B CB }
        $b = { 8B F0 85 C0 0F 89 B8 00 00 00 49 83 FE FF 0F 85 AE 00 00 00 48 8B 55 10 }
    condition:
        all of them
}

