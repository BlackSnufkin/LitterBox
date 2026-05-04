rule Windows_Cryptominer_Generic_dd1e4d1a {
    meta:
        author = "Elastic Security"
        id = "dd1e4d1a-2e2f-4af0-bd66-2e12367dd064"
        fingerprint = "a00e3e08e11d10a7a4bf1110a5110e4d0a4d2acf0974aca9dfc1ad5f21c80df7"
        creation_date = "2021-01-12"
        last_modified = "2021-08-23"
        threat_name = "Windows.Cryptominer.Generic"
        reference_sample = "7ac1d7b6107307fb2442522604c8fa56010d931392d606ac74dcea6b7125954b"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { EF F9 66 0F EF FA 66 0F FE FE 66 0F 6F B0 B0 00 00 00 66 0F }
    condition:
        all of them
}

rule Windows_Cryptominer_Generic_f53cfb9b {
    meta:
        author = "Elastic Security"
        id = "f53cfb9b-0286-4e7e-895e-385b6f64c58a"
        fingerprint = "2b66960ee7d423669d0d9e9dcd22ea6e1c0843893e5e04db92237b67b43d645c"
        creation_date = "2024-03-05"
        last_modified = "2024-06-12"
        threat_name = "Windows.Cryptominer.Generic"
        reference_sample = "a9870a03ddc6543a5a12d50f95934ff49f26b60921096b2c8f2193cb411ed408"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 81 EC B8 00 00 00 0F AE 9C 24 10 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0F AE 94 24 14 01 00 00 4C 8B A9 E0 00 00 00 4C 8B CA 4C 8B 51 20 4C 8B C1 4C 33 11 ?? ?? ?? ?? ?? ?? 4C 8B 59 28 }
    condition:
        all of them
}

