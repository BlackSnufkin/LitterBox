rule Windows_Trojan_SourShark_f0247cce {
    meta:
        author = "Elastic Security"
        id = "f0247cce-b983-41a1-9118-fd4c23e3d099"
        fingerprint = "174d6683890b855a06c672423b4a0b3aa291558d8a2af4771b931d186ce3cb63"
        creation_date = "2024-06-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Trojan.SourShark"
        reference_sample = "07eb88c69437ee6e3ea2fbab5f2fbd8e846125d18c1da7d72bb462e9d083c9fc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%s\\svchost.%s"
        $a2 = "crypto_domain"
        $a3 = "postback_id"
    condition:
        all of them
}

rule Windows_Trojan_SourShark_adee8a17 {
    meta:
        author = "Elastic Security"
        id = "adee8a17-cc0c-40b8-9ee6-a01b41e9befd"
        fingerprint = "f35ebe8a220693ef6288efae0d325c3f40e70836c088599cb9b620c59fab09da"
        creation_date = "2024-06-04"
        last_modified = "2024-06-12"
        threat_name = "Windows.Trojan.SourShark"
        reference_sample = "07eb88c69437ee6e3ea2fbab5f2fbd8e846125d18c1da7d72bb462e9d083c9fc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8B 45 08 8B 4C BE 08 8A 04 02 02 C3 02 C1 0F B6 D8 8B 44 9E 08 89 44 BE 08 8D 42 01 33 D2 89 4C 9E 08 47 83 F8 20 0F 4C D0 81 FF 00 01 00 00 7C CF 8B 16 33 FF 8B 5E 04 39 7D FC 7E 33 0F 1F 00 }
    condition:
        all of them
}

