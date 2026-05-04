rule Linux_Trojan_Rekoobe_e75472fa {
    meta:
        author = "Elastic Security"
        id = "e75472fa-0263-4a47-a3bd-2d1bb14df177"
        fingerprint = "4e7605685ba7ba53afeafdef7e46bdca76109bd4d8b9116a93c301edeff606ee"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "8d2a9e363752839a09001a9e3044ab7919daffd9d9aee42d936bc97394164a88"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 83 F8 01 74 1F 89 D0 48 8B 4C 24 08 64 48 33 0C 25 28 00 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_52462fe8 {
    meta:
        author = "Elastic Security"
        id = "52462fe8-a40c-4620-b539-d0c1f9d2ceee"
        fingerprint = "e09e8e023b3142610844bf7783c5472a32f63c77f9a46edc028e860da63e6eeb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "c1d8c64105caecbd90c6e19cf89301a4dc091c44ab108e780bdc8791a94caaad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 1C D8 48 8B 5A E8 4A 33 0C DE 48 89 4A E0 89 D9 C1 E9 18 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_de9e7bdf {
    meta:
        author = "Elastic Security"
        id = "de9e7bdf-c515-4af8-957a-e489b7cb9716"
        fingerprint = "ab3f0b9179a136f7c1df43234ba3635284663dee89f4e48d9dfc762fb762f0db"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "447da7bee72c98c2202f1919561543e54ec1b9b67bd67e639b9fb6e42172d951"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F5 48 89 D6 48 C1 EE 18 40 0F B6 F6 48 33 2C F1 48 89 D6 48 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_b41f70c2 {
    meta:
        author = "Elastic Security"
        id = "b41f70c2-abe4-425a-952f-5e0c9e572a76"
        fingerprint = "396fcb4333abe90f4c228d06c20eeff40f91e25fde312cc7760d999da0aa1027"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "19c1a54279be1710724fc75a112741575936fe70379d166effc557420da714cd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E2 10 4D 31 D1 0F B6 D6 48 8B 14 D1 48 C1 E2 08 4C 31 CA 48 89 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_1d307d7c {
    meta:
        author = "Elastic Security"
        id = "1d307d7c-cc84-44e5-8fa0-eda9fffb3964"
        fingerprint = "11b1474dbdc376830bca50dbeea7f7f786c8a9b2ac51a139c4e06bed7c867121"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "00bc669f79b2903c5d9e6412050655486111647c646698f9a789e481a7c98662"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 01 75 56 83 7C 24 3C 10 75 1C BE ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_7f7aba78 {
    meta:
        author = "Elastic Security"
        id = "7f7aba78-6e64-41c4-a542-088a8270a941"
        fingerprint = "acb8f0fb7a7b0c5329afeadb70fc46ab72a7704cdeef64e7575fbf2c2dd3dbe2"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "50b73742726b0b7e00856e288e758412c74371ea2f0eaf75b957d73dfb396fd7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F0 89 D0 31 D8 21 F0 31 D8 03 45 F0 89 CF C1 CF 1B 01 F8 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_ab8ba790 {
    meta:
        author = "Elastic Security"
        id = "ab8ba790-d2dd-4756-af5c-6f78ba10c92d"
        fingerprint = "decdd02a583562380eda405dcb892d38558eb868743ebc44be592f4ae95b5971"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "2aee0c74d9642ffab1f313179c26400acf60d7cbd2188bade28534d403f468d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { DB F9 66 0F 71 D1 08 66 0F 67 DD 66 0F DB E3 66 0F 71 D3 08 66 0F }
    condition:
        all of them
}

