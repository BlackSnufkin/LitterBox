rule Linux_Trojan_Ircbot_bb204b81 {
    meta:
        author = "Elastic Security"
        id = "bb204b81-db58-434f-b834-672cdc25e56c"
        fingerprint = "66f9a8a31653a5e480f427d2d6a25b934c2c53752308eedb57eaa7b7cb7dde2e"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ircbot"
        reference_sample = "6147481d083c707dc98905a1286827a6e7009e08490e7d7c280ed5a6356527ad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 44 C8 4C 5E F8 8D EF 80 83 CD FF 31 DB 30 22 }
    condition:
        all of them
}

rule Linux_Trojan_Ircbot_7c60454d {
    meta:
        author = "Elastic Security"
        id = "7c60454d-8290-4e91-9b0a-2392aebe1bec"
        fingerprint = "4f14dcca5704c2ef32caaed1c048a5fb14095f31be8630676c07cbc8b22e6c4d"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Ircbot"
        reference_sample = "14eeff3516de6d2cb11d6ada4026e3dcee1402940e3a0fb4fa224a5c030049d8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 49 89 F0 41 54 55 48 89 CD 53 48 89 FB 48 83 EC 58 48 85 D2 }
    condition:
        all of them
}

