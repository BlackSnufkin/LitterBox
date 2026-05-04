rule Windows_Trojan_GuidLoader_d3a30cec {
    meta:
        author = "Elastic Security"
        id = "d3a30cec-7145-41a9-b6a6-84ab02068a83"
        fingerprint = "609619490d36ddea6e4bc925278c5717048a2affa37dc81d346b841cdb45cab6"
        creation_date = "2025-01-10"
        last_modified = "2025-02-11"
        threat_name = "Windows.Trojan.GuidLoader"
        reference_sample = "f90420847e1f2378ac8c52463038724533a9183f02ce9ad025a6a10fd4327f12"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq1 = { 75 ?? B9 88 13 00 00 FF 15 ?? ?? ?? ?? 48 FF C? 48 83 F? }
        $seq2 = { 48 8B 55 ?? 48 83 FA 10 72 ?? 48 FF C2 48 8B 4D ?? 48 8B C1 48 81 FA 00 10 00 00 }
        $seq3 = { C1 E8 ?? 03 D0 0F BE C2 6B C8 ?? 41 0F B6 C0 41 FF C0 2A C1 04 ?? 41 30 41 ?? 41 83 F8 ?? 7C ?? }
        $seq4 = { 66 0F DB 15 ?? ?? 00 00 66 0F 67 D2 66 0F FC 15 ?? ?? 00 00 66 0F EF D0 66 0F 62 CB }
        $seq5 = "Download" ascii fullword
    condition:
        4 of them
}

