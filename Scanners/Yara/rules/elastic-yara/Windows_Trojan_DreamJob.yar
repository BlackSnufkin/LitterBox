rule Windows_Trojan_DreamJob_00cf26dc {
    meta:
        author = "Elastic Security"
        id = "00cf26dc-a50f-4aef-91ae-71fd8296d7ab"
        fingerprint = "90702147cede06b3f657ebb7970e0b5192069336c50546069559aa8c3616c106"
        creation_date = "2024-12-27"
        last_modified = "2025-02-11"
        threat_name = "Windows.Trojan.DreamJob"
        reference_sample = "0c69fd9be0cc9fadacff2c0bacf59dab6d935b02b5b8d2c9cb049e9545bb55ce"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $binary_0 = { 65 77 F2 CA [3-6] D1 BF 63 75 [3-6] C1 6D 7F BE [3-6] 6A 7E DE 87 [3-6] 9C D5 84 9A [3-6] C1 7E 92 D8 }
        $str_0 = "Cookie=Enable&CookieV=%d&Cookie_Time="
        $str_1 = "Authentication Success" fullword
        $str_2 = "Cookie=Enable" fullword
        $str_3 = "Authentication Error" fullword
        $str_4 = "%d-101010" fullword
        $str_5 = "%d-202020" fullword
    condition:
        $binary_0 or 4 of ($str_*)
}

