rule Linux_Cryptominer_Xmrminer_70c153b5 {
    meta:
        author = "Elastic Security"
        id = "70c153b5-2628-4504-8f21-2c7f0201b133"
        fingerprint = "51d304812e72045387b002824fdc9231d64bf4e8437c70150625c4b2aa292284"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "55b133ba805bb691dc27a5d16d3473650360c988e48af8adc017377eed07935b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EC 18 BA 08 00 00 00 48 8D 4C 24 08 48 89 74 24 08 BE 02 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_98b00f9c {
    meta:
        author = "Elastic Security"
        id = "98b00f9c-354a-47dd-8546-a2842559d247"
        fingerprint = "8d231a490e818614141d6805a9e7328dc4b116b34fd027d5806043628b347141"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "c01b88c5d3df7ce828e567bd8d639b135c48106e388cd81497fcbd5dcf30f332"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 38 DC DF 49 89 D4 66 0F 7F 24 1A 66 0F EF C3 66 42 0F 7F }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_2b250178 {
    meta:
        author = "Elastic Security"
        id = "2b250178-3f9a-4aeb-819a-970b5ef9c98a"
        fingerprint = "e297a790a78d32b973d6a028a09c96186c3971279b5c5eea4ff6409f12308e67"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "636605cf63d3e335fe9481d4d110c43572e9ab365edfa2b6d16d96b52d6283ef"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 03 7E 11 8B 44 24 38 89 EF 31 D2 89 06 8B 44 24 3C 89 46 04 F7 C7 02 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_67bf4b54 {
    meta:
        author = "Elastic Security"
        id = "67bf4b54-aa02-4f4c-ba70-3f2db1418c7e"
        fingerprint = "5f2fae0eee79dac3c202796d987ad139520fadae145c84ab5769d46afb2518c2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "9d33fba4fda6831d22afc72bf3d6d5349c5393abb3823dfa2a5c9e391d2b9ddf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 46 70 4A 8B 2C E0 83 7D 00 03 74 DA 8B 4D 68 85 C9 74 DC 45 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_504b42ca {
    meta:
        author = "Elastic Security"
        id = "504b42ca-00a7-4917-8bb1-1957838a1d27"
        fingerprint = "265a3cb860e1f0ddafbe5658fa3a341d7419c89eecc350f8fc16e7a1e05a7673"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D7 8B 04 8C 44 8D 50 FF 4C 89 04 C6 44 89 14 8C 75 D7 48 8B 2E 45 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_d1bb752f {
    meta:
        author = "Elastic Security"
        id = "d1bb752f-f5d6-4d93-96af-d977b501776a"
        fingerprint = "0f2455a4e80d93e7f1e420dc2f36e89c28ecb495879bca2e683a131b2770c3ee"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "bea55bc9495ee51c78ceedadf3a685ea9d6dd428170888c67276c100d4d94beb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 12 48 29 C8 48 2B 83 B0 00 00 00 48 C1 E8 03 48 F7 E2 48 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_d625fcd2 {
    meta:
        author = "Elastic Security"
        id = "d625fcd2-2951-4ecf-91cd-d58e16c33c65"
        fingerprint = "08c8d00e38fbf62cbf0aa329d6293fba302c3c76aee8c33341260329c14a58aa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 00 00 40 00 0C C0 5C 02 60 01 02 03 12 00 40 04 50 09 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_02d19c01 {
    meta:
        author = "Elastic Security"
        id = "02d19c01-51e9-4a46-a06b-d5f7e97285d9"
        fingerprint = "724bbc2910217bcac457e6ba0c0848caf38e12f272b0104ade1c7bc57dc85c27"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "b6df662f5f7566851b95884c0058e7476e49aeb7a96d2aa203393d88e584972f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4C 8D 7E 15 41 56 41 55 41 54 41 BB 03 00 00 00 55 53 48 89 FB 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_d1a814b0 {
    meta:
        author = "Elastic Security"
        id = "d1a814b0-38a6-4469-a29b-75787f52d789"
        fingerprint = "1746bc1d96207bd1bb44e9ff248b76245feb76c1d965400c3abd3b9116ea8455"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "bea55bc9495ee51c78ceedadf3a685ea9d6dd428170888c67276c100d4d94beb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 48 8B 44 24 58 49 89 41 08 8B 01 48 C1 E0 05 4D 8D 04 07 48 8B 44 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_c6218e30 {
    meta:
        author = "Elastic Security"
        id = "c6218e30-1a49-46ea-aac8-5f0f652156c5"
        fingerprint = "c3171cf17ff3b0ca3d5d62fd4c2bd02a4e0a8616a84ea5ef9e78307283e4a360"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "b43ddd8e355b0c538c123c43832e7c8c557e4aee9e914baaed0866ee5d68ee55"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { AC 24 B0 00 00 00 48 89 FA 66 0F EF DD 48 C1 E2 20 66 41 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_b17a7888 {
    meta:
        author = "Elastic Security"
        id = "b17a7888-dc12-4bb4-bc77-558223814e8b"
        fingerprint = "2b11457488e6098d777fb0d8f401cf10af5cd48e05248b89cb9e377d781b516c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "65c9fdd7c559554af06cd394dcebece1bc0fdc7dd861929a35c74547376324a6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D4 FF C5 55 F4 C9 C5 F5 D4 CD C4 41 35 D4 C9 C5 B5 D4 C9 C5 C5 }
    condition:
        all of them
}

