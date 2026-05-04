rule MacOS_Trojan_Generic_a829d361 {
    meta:
        author = "Elastic Security"
        id = "a829d361-ac57-4615-b8e9-16089c44d7af"
        fingerprint = "5dba43dbc5f4d5ee295e65d66dd4e7adbdb7953232faf630b602e6d093f69584"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Generic"
        reference_sample = "5b2a1cd801ae68a890b40dbd1601cdfeb5085574637ae8658417d0975be8acb5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { E7 81 6A 12 EA A8 56 6C 86 94 ED F6 E8 D7 35 E1 EC 65 47 BA 8E 46 2C A6 14 5F }
    condition:
        all of them
}

rule MacOS_Trojan_Generic_2e2a36d3 {
    meta:
        author = "Elastic Security"
        id = "2e2a36d3-48ee-41c5-b470-d366f8b21c2c"
        fingerprint = "e4f6ccdf231d2e7cf79f3ab435c57d11196d3b219faa447bd082c147b964a2e8"
        creation_date = "2026-02-25"
        last_modified = "2026-04-06"
        threat_name = "MacOS.Trojan.Generic"
        reference_sample = "4cd5df82e1d4f93361e71624730fbd1dd2f8ccaec7fc7cbdfa87497fb5cb438c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "InjectAmd64"
        $a2 = "InjectWithDyld" ascii fullword
        $a3 = { 45 31 ED 43 81 7C 2F 08 01 00 00 07 }
        $a4 = { 43 81 7C 2F 08 01 00 00 07 75 1C }
    condition:
        all of them
}

