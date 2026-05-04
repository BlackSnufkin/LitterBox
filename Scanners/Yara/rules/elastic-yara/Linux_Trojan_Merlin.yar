rule Linux_Trojan_Merlin_55beddd3 {
    meta:
        author = "Elastic Security"
        id = "55beddd3-735b-4e0c-a387-e6a981cd42a3"
        fingerprint = "54e03337930d74568a91e797cfda3b7bfbce3aad29be2543ed58c51728d8e185"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Merlin"
        reference_sample = "15ccdf2b948fe6bd3d3a7f5370e72cf3badec83f0ec7f47cdf116990fb551adf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { AF F0 4C 01 F1 4C 8B B4 24 A8 00 00 00 4D 0F AF F4 4C 01 F1 4C 8B B4 24 B0 00 }
    condition:
        all of them
}

rule Linux_Trojan_Merlin_bbad69b8 {
    meta:
        author = "Elastic Security"
        id = "bbad69b8-e8fc-43ce-a620-793c059536fd"
        fingerprint = "594f385556978ef1029755cea53c3cf89ff4d6697be8769fe1977b14bbdb46d1"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Merlin"
        reference_sample = "d9955487f7d08f705e41a5ff848fb6f02d6c88286a52ec837b7b555fb422d1b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { DA 31 C0 BB 1F 00 00 00 EB 12 0F B6 3C 13 40 88 3C 02 40 88 }
    condition:
        all of them
}

rule Linux_Trojan_Merlin_c6097296 {
    meta:
        author = "Elastic Security"
        id = "c6097296-c518-4541-99b2-e2f6d3e4610b"
        fingerprint = "8496ec66e276304108184db36add64936500f1f0dd74120e03b78c64ac7b5ba1"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Merlin"
        reference_sample = "d9955487f7d08f705e41a5ff848fb6f02d6c88286a52ec837b7b555fb422d1b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 24 38 48 89 5C 24 48 48 85 C9 75 62 48 85 D2 75 30 48 89 9C 24 C8 00 }
    condition:
        all of them
}

