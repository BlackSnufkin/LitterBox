rule Windows_Trojan_HazelCobra_6a9fe48a {
    meta:
        author = "Elastic Security"
        id = "6a9fe48a-6fd9-4bce-ac43-254c02d6b3a4"
        fingerprint = "4dc883be5fb6aae0dac0ec5d64baf24f0f3aaded6d759ec7dccb1a2ae641ae7b"
        creation_date = "2023-11-01"
        last_modified = "2023-11-01"
        threat_name = "Windows.Trojan.HazelCobra"
        reference_sample = "b5acf14cdac40be590318dee95425d0746e85b1b7b1cbd14da66f21f2522bf4d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 E9 37 48 63 C2 F6 C2 01 75 0C C0 E1 04 48 D1 F8 88 4C 04 40 EB 07 }
        $s1 = "Data file loaded. Running..." fullword
        $s2 = "No key in args" fullword
        $s3 = "Can't read data file" fullword
    condition:
        $a1 or all of ($s*)
}

