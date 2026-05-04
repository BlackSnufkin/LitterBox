rule MacOS_Trojan_Adload_4995469f {
    meta:
        author = "Elastic Security"
        id = "4995469f-9810-4c1f-b9bc-97e951fe9256"
        fingerprint = "9b7e7c76177cc8ca727df5039a5748282f5914f2625ec1f54d67d444f92f0ee5"
        creation_date = "2021-10-04"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Adload"
        reference_sample = "6464ca7b36197cccf0dac00f21c43f0cb09f900006b1934e2b3667b367114de5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 49 8B 77 08 49 8B 4F 20 48 BF 89 88 88 88 88 88 88 88 48 89 C8 48 F7 E7 48 C1 }
    condition:
        all of them
}

rule MacOS_Trojan_Adload_9b9f86c7 {
    meta:
        author = "Elastic Security"
        id = "9b9f86c7-e74c-4fc2-bb64-f87473a4b820"
        fingerprint = "7e70d5574907261e73d746a4ad0b7bce319a9bb3b39a7f1df326284960a7fa38"
        creation_date = "2021-10-04"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Adload"
        reference_sample = "952e6004ce164ba607ac7fddc1df3d0d6cac07d271d90be02d790c52e49cb73c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 44 65 6C 65 67 61 74 65 43 35 73 68 6F 77 6E 53 62 76 70 57 76 64 }
    condition:
        all of them
}

rule MacOS_Trojan_Adload_f6b18a0a {
    meta:
        author = "Elastic Security"
        id = "f6b18a0a-7593-430f-904b-8d416861d165"
        fingerprint = "f33275481b0bf4f4e57c7ad757f1e22d35742fc3d0ffa3983321f03170b5100e"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Adload"
        reference_sample = "06f38bb811e6a6c38b5e2db708d4063f4aea27fcd193d57c60594f25a86488c8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 10 49 8B 4E 20 48 BE 89 88 88 88 88 88 88 88 48 89 C8 48 F7 E6 49 39 DC 0F 84 }
    condition:
        all of them
}

