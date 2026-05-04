rule Linux_Cryptominer_Generic_d7bd0e5d {
    meta:
        author = "Elastic Security"
        id = "d7bd0e5d-3528-4648-aaa5-6cf44d22c0d5"
        fingerprint = "fbc06c7603aa436df807ad3f77d5ba783c4d33f61b06a69e8641741068f3a543"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "afcfd67af99e437f553029ccf97b91ed0ca891f9bcc01c148c2b38c75482d671"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CF 99 67 D8 37 AA 24 80 F2 F3 47 6A A5 5E 88 50 F1 28 61 18 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_69e1a763 {
    meta:
        author = "Elastic Security"
        id = "69e1a763-1e0d-4448-9bc4-769f3a36ac10"
        fingerprint = "9007ab73902ef9bfa69e4ddc29513316cb6aa7185986cdb10fd833157cd7d434"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "b04d9fabd1e8fc42d1fa8e90a3299a3c36e6f05d858dfbed9f5e90a84b68bcbb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 43 08 49 89 46 08 48 8B 43 10 49 89 46 10 48 85 C0 74 8A F0 83 40 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_397a86bd {
    meta:
        author = "Elastic Security"
        id = "397a86bd-6d66-4db0-ad41-d0ae3dbbeb21"
        fingerprint = "0bad343f28180822bcb45b0a84d69b40e26e5eedb650db1599514020b6736dd0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "79c47a80ecc6e0f5f87749319f6d5d6a3f0fbff7c34082d747155b9b20510cde"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 4F 48 8B 75 00 48 8B 4D 08 4C 89 F7 48 8B 55 10 48 8B 45 18 48 89 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_37c3f8d3 {
    meta:
        author = "Elastic Security"
        id = "37c3f8d3-9d79-434c-b0e8-252122ebc62a"
        fingerprint = "6ba0bae987db369ec6cdadf685b8c7184e6c916111743f1f2b43ead8d028338c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "efbddf1020d0845b7a524da357893730981b9ee65a90e54976d7289d46d0ffd4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F0 4C 01 F0 49 8B 75 08 48 01 C3 49 39 F4 74 29 48 89 DA 4C }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_28a80546 {
    meta:
        author = "Elastic Security"
        id = "28a80546-ae74-4616-8896-50f54da66650"
        fingerprint = "7f49f04ba36e7ff38d313930c469d64337203a60792f935a3548cee176ae9523"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "96cc225cf20240592e1dcc8a13a69f2f97637ed8bc89e30a78b8b2423991d850"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 72 59 D4 B5 63 E2 4D B6 08 EF E8 0A 3A B1 AD 1B 61 6E 7C 65 D1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_9d531f70 {
    meta:
        author = "Elastic Security"
        id = "9d531f70-c42f-4e1a-956a-f9ac43751e73"
        fingerprint = "2c6019f7bc2fc47d7002e0ba6e35513950260b558f1fdc732d3556dabbaaa93d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "36f2ce4e34faf42741f0a15f62e8b3477d69193bf289818e22d0e3ee3e906eb0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 49 10 58 00 10 D4 34 80 08 30 01 20 02 00 B1 00 83 49 23 16 54 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_23a5c29a {
    meta:
        author = "Elastic Security"
        id = "23a5c29a-6a8f-46f4-87ba-2a60139450ce"
        fingerprint = "1a7a86ff6e1666c2da6e6f65074bb1db2fe1c97d1ad42d1f670dd5c88023eecf"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "1320d7a2b5e3b65fe974a95374b4ea7ed1a5aa27d76cd3d9517d3a271121103f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C1 48 29 D0 48 01 C0 4D 8B 39 48 29 C1 49 29 F8 48 8D 04 C9 4D 8D }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_ea5703ce {
    meta:
        author = "Elastic Security"
        id = "ea5703ce-4ad4-46cc-b253-8d022ca385a3"
        fingerprint = "a58a41ab4602380c0989659127d099add042413f11e3815a5e1007a44effaa68"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "bec6eea63025e2afa5940d27ead403bfda3a7b95caac979079cabef88af5ee0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 94 C0 EB 05 B8 01 00 00 00 44 21 E8 48 8B 4C 24 08 64 48 33 0C 25 28 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_6a4f4255 {
    meta:
        author = "Elastic Security"
        id = "6a4f4255-d202-48b7-96ae-cb7211dcbea3"
        fingerprint = "0ed37d7eccd4e36b954824614b976e1371c3b2ffe318345d247198d387a13de6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FD 48 8D 5D 01 4C 8D 14 1B 48 C1 E3 05 4C 01 EB 4D 8D 7A FF F2 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_9088d00b {
    meta:
        author = "Elastic Security"
        id = "9088d00b-622a-4cbf-9600-6dfcf2fc0c2c"
        fingerprint = "85cbe86b9f96fc1b6899b35cc4aa16b66a91dc1239ed5f5cf3609322cec30f30"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "8abb2b058ec475b0b6fd0c994685db72e98d87ee3eec58e29cf5c324672df04a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2C 1C 77 16 48 8B 44 24 08 64 48 33 04 25 28 00 00 00 75 24 48 83 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_71024c4a {
    meta:
        author = "Elastic Security"
        id = "71024c4a-e8da-44fc-9cf9-c71829dfe87a"
        fingerprint = "dbbb74ec687e8e9293dfa2272d55b81ef863a50b0ff87daf15aaf6cee473efe6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "afe81c84dcb693326ee207ccd8aeed6ed62603ad3c8d361e8d75035f6ce7c80f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 46 08 48 89 45 08 48 8B 46 10 48 85 C0 48 89 45 10 74 BC F0 FF }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_d81368a3 {
    meta:
        author = "Elastic Security"
        id = "d81368a3-00ca-44cf-b009-718272d389eb"
        fingerprint = "dd463df2c03389af3e7723fda684b0f42342817b3a76664d131cf03542837b8a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "71225e4702f2e0a0ecf79f7ec6c6a1efc95caf665fda93a646519f6f5744990b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CB 49 C1 E3 04 49 01 FB 41 8B 13 39 D1 7F 3F 7C 06 4D 3B 43 08 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_97e9cebe {
    meta:
        author = "Elastic Security"
        id = "97e9cebe-d30b-49f6-95f4-fd551e7a42e4"
        fingerprint = "61bef39d174d97897ac0820b624b1afbfe73206208db420ae40269967213ebed"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "b4ff62d92bd4d423379f26b37530776b3f4d927cc8a22bd9504ef6f457de4b7a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 04 25 28 00 00 00 48 89 44 24 58 31 C0 49 83 FF 3F 48 89 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_98ff0f36 {
    meta:
        author = "Elastic Security"
        id = "98ff0f36-5faf-417a-9431-8a44e9f088f4"
        fingerprint = "b25420dfc32522a060dc8470315409280e3c03de0b347e92a5bc6c1a921af94a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "4c14aaf05149bb38bbff041432bf9574dd38e851038638aeb121b464a1e60dcc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 A8 8B 00 89 C2 48 8B 45 C8 48 01 C2 8B 45 90 48 39 C2 7E 08 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_1512cf40 {
    meta:
        author = "Elastic Security"
        id = "1512cf40-ae62-40cf-935d-589be4fe3d93"
        fingerprint = "f9800996d2e6d9ea8641d51aedc554aa732ebff871f0f607bb3fe664914efd5a"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "fc063a0e763894e86cdfcd2b1c73d588ae6ecb411c97df2a7a802cd85ee3f46d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C4 10 5B C3 E8 35 A7 F6 FF 0F 1F 44 00 00 53 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_0d6005a1 {
    meta:
        author = "Elastic Security"
        id = "0d6005a1-a481-4679-a214-f1e3ef8bf1d0"
        fingerprint = "435040ec452d337c60435b07622d3a8af8e3b7e8eb6ec2791da6aae504cc2266"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "230d46b39b036552e8ca6525a0d2f7faadbf4246cdb5e0ac9a8569584ef295d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 79 73 00 6E 6F 5F 6D 6C 63 6B 00 77 61 72 6E 00 6E 65 76 65 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e1ff020a {
    meta:
        author = "Elastic Security"
        id = "e1ff020a-446c-4537-8cc3-3bcc56ba5a99"
        fingerprint = "363872fe6ef89a0f4c920b1db4ac480a6ae70e80211200b73a804b43377fff01"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "5b611898f1605751a3d518173b5b3d4864b4bb4d1f8d9064cc90ad836dd61812"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F B6 4F 3D 0B 5C 24 F4 41 C1 EB 10 44 0B 5C 24 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_102d6f7c {
    meta:
        author = "Elastic Security"
        id = "102d6f7c-0e77-4b23-9e84-756aba929d83"
        fingerprint = "037b1da31ffe66015c959af94d89eef2f7f846e1649e4415c31deaa81945aea9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "bd40c2fbf775e3c8cb4de4a1c7c02bc4bcfa5b459855b2e5f1a8ab40f2fb1f9e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 70 D2 AA C5 F9 EF D2 C5 F1 EF CB C5 E1 73 FB 04 C4 E3 79 DF }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_9c8f3b1a {
    meta:
        author = "Elastic Security"
        id = "9c8f3b1a-0273-4164-ba48-b0bc090adf9e"
        fingerprint = "a35efe6bad4e0906032ab2fd7c776758e71caed8be402948f39682cf1f858005"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "74d8344139c5deea854d8f82970e06fc6a51a6bf845e763de603bde7b8aa80ac"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6F 67 31 70 00 6C 6F 67 32 66 00 6C 6C 72 6F 75 6E 64 00 73 71 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_76cb94a9 {
    meta:
        author = "Elastic Security"
        id = "76cb94a9-5a3f-483c-91f3-aa0e3c27f7ba"
        fingerprint = "623a33cc95af46b8f0d557c69f8bf72db7c57fe2018b7a911733be4ddd71f073"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "1320d7a2b5e3b65fe974a95374b4ea7ed1a5aa27d76cd3d9517d3a271121103f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8C 24 98 00 00 00 31 C9 80 7A 4A 00 48 89 74 24 18 48 89 54 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_616afaa1 {
    meta:
        author = "Elastic Security"
        id = "616afaa1-7679-4198-9e80-c3f044b3c07d"
        fingerprint = "fd6afad9f318ce00b0f0f8be3a431a2c7b4395dd69f82328f4555b3715a8b298"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "0901672d2688660baa26fdaac05082c9e199c06337871d2ae40f369f5d575f71"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4B 04 31 C0 41 8B 14 07 89 14 01 48 83 C0 04 48 83 F8 14 75 EF 4C 8D 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_18af74b2 {
    meta:
        author = "Elastic Security"
        id = "18af74b2-99fe-42fc-aacd-7887116530a8"
        fingerprint = "07a6b44ff1ba6143c76e7ccb3885bd04e968508e93c5f8bff9bc5efc42a16a96"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "52707aa413c488693da32bf2705d4ac702af34faee3f605b207db55cdcc66318"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 70 6F 77 00 6C 6F 67 31 70 00 6C 6F 67 32 66 00 63 65 69 6C 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_1b76c066 {
    meta:
        author = "Elastic Security"
        id = "1b76c066-463c-46e5-8a08-ccfc80e3f399"
        fingerprint = "e33937322a1a2325539d7cdb1df13295e5ca041a513afe1d5e0941f0c66347dd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "f60302de1a0e756e3af9da2547a28da5f57864191f448e341af1911d64e5bc8b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0C 14 89 0C 10 48 83 C2 04 48 83 FA 20 75 EF 48 8D 8C 24 F0 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_b6ea5ee1 {
    meta:
        author = "Elastic Security"
        id = "b6ea5ee1-ede5-4fa3-a065-99219b3530da"
        fingerprint = "07c2f1fcb50ce5bcdebfc03fca4aaacdbabab42a857d7cc8f008712ca576b871"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "19b442c9aa229cd724ed9cbaa73f9dfaf0ed61aa3fd1bee7bf8ba964fc23a2b8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 47 20 49 8D 77 20 4C 89 74 24 10 4C 89 6C 24 18 4C 89 64 24 20 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_050ac14c {
    meta:
        author = "Elastic Security"
        id = "050ac14c-9aef-4212-97fd-e2a21c2f62e2"
        fingerprint = "6f0a5a5d3cece7ae8db47ef5e1bbbea02b886e865f23b0061c2d346feb351663"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "36f2ce4e34faf42741f0a15f62e8b3477d69193bf289818e22d0e3ee3e906eb0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 47 08 49 3B 47 10 74 3C 48 85 C0 74 16 48 8B 13 48 89 10 48 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_df937caa {
    meta:
        author = "Elastic Security"
        id = "df937caa-ca6c-4a80-a68c-c265dab7c02c"
        fingerprint = "963642e141db6c55bd8251ede57b38792278ded736833564ae455cc553ab7d24"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "19b442c9aa229cd724ed9cbaa73f9dfaf0ed61aa3fd1bee7bf8ba964fc23a2b8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 04 62 20 0A 10 02 0A 14 60 29 00 02 0C 24 14 60 7D 44 01 70 01 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e9ff82a8 {
    meta:
        author = "Elastic Security"
        id = "e9ff82a8-b8ca-45fb-9738-3ce0c452044f"
        fingerprint = "91e78b1777a0580f25f7796aa6d9bcbe2cbad257576924aecfe513b1e1206915"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "62ea137e42ce32680066693f02f57a0fb03483f78c365dffcebc1f992bb49c7a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D9 4D 01 CA 4C 89 74 24 D0 4C 8B 74 24 E8 4D 31 D4 49 C1 C4 20 48 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_a5267ea3 {
    meta:
        author = "Elastic Security"
        id = "a5267ea3-b98c-49e9-8051-e33a101f12d3"
        fingerprint = "8391a4dbc361eec2877852acdc77681b3a15922d9a047d7ad12d06271d53f540"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "b342ceeef58b3eeb7a312038622bcce4d76fc112b9925379566b24f45390be7d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EE 6A 00 41 B9 01 00 00 00 48 8D 4A 13 4C 89 E7 88 85 40 FF }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_4e9075e6 {
    meta:
        author = "Elastic Security"
        id = "4e9075e6-3ca9-459e-9f5f-3e614fd4f1c8"
        fingerprint = "70d8c4ecb185b8817558ad9d26a47c340c977abb6abfca8efe1ff99efb43c579"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "098bf2f1ce9d7f125e1c9618f349ae798a987316e95345c037a744964277f0fe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2C 24 74 67 48 89 5C 24 18 4C 89 6C 24 20 4C 89 FB 4D 89 E5 4C 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_3a8d0974 {
    meta:
        author = "Elastic Security"
        id = "3a8d0974-384e-4d62-9aa8-0bd8f7d50206"
        fingerprint = "60cb81033461e73fcb0fb8cafd228e2c9478c132f49e115c5e55d5579500caa2"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference = "193fe9ea690759f8e155458ef8f8e9efe9efc8c22ec8073bbb760e4f96b5aef7"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 07 41 89 34 06 48 83 C0 04 48 83 F8 20 75 EF 8B 42 D4 66 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_b9e6ffdf {
    meta:
        author = "Elastic Security"
        id = "b9e6ffdf-4b2b-4052-9c91-a06f43a2e7b8"
        fingerprint = "fdd91d5802d5807d52f4c9635e325fc0765bb54cf51305c7477d2b791f393f3e"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "c0f3200a93f1be4589eec562c4f688e379e687d09c03d1d8850cc4b5f90f192a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 D8 48 83 C4 20 5B C3 0F 1F 00 BF ?? ?? 40 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_7ef74003 {
    meta:
        author = "Elastic Security"
        id = "7ef74003-cd1f-4f2f-9c96-4dbcabaa36e4"
        fingerprint = "187fd82b91ae6eadc786cadac75de5d919a2b8a592037a5bf8da2efa2539f507"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "a172cfecdec8ebd365603ae094a16e247846fdbb47ba7fd79564091b7e8942a0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 56 45 31 F6 41 55 49 89 F5 41 54 44 8D 67 01 55 4D 63 E4 53 49 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_1d0700b8 {
    meta:
        author = "Elastic Security"
        id = "1d0700b8-1bc0-4da2-a903-9d78e79e71d8"
        fingerprint = "19853be803f82e6758554a57981e1b52c43a017ab88242c42a7c39f6ead01cf3"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "de59bee1793b88e7b48b6278a52e579770f5204e92042142cc3a9b2d683798dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 30 42 30 42 00 22 22 03 5C DA 10 00 C0 00 60 43 9C 64 48 00 00 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_55beb2ee {
    meta:
        author = "Elastic Security"
        id = "55beb2ee-7306-4134-a512-840671cc4490"
        fingerprint = "707a1478f86da2ec72580cfe4715b466e44c345deb6382b8dc3ece4e3935514d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "edda1c6b3395e7f14dd201095c1e9303968d02c127ff9bf6c76af6b3d02e80ad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 FC 00 00 00 8B 84 24 C0 00 00 00 0F 29 84 24 80 00 00 00 0F 11 94 24 C4 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_fdd7340f {
    meta:
        author = "Elastic Security"
        id = "fdd7340f-49d6-4770-afac-24104a3c2f86"
        fingerprint = "cc302eb6c133901cc3aa78e6ca0af16a620eb4dabb16b21d9322c4533f11d25f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "de59bee1793b88e7b48b6278a52e579770f5204e92042142cc3a9b2d683798dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EA 48 89 DE 48 8D 7C 24 08 FF 53 18 48 8B 44 24 08 48 83 78 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e36a35b0 {
    meta:
        author = "Elastic Security"
        id = "e36a35b0-cb38-4d2d-bca2-f3734637faa8"
        fingerprint = "0ee42ff704c82ee6c2bc0408cccb77bcbae8d4405bb1f405ee09b093e7a626c0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "ab6d8f09df67a86fed4faabe4127cc65570dbb9ec56a1bdc484e72b72476f5a4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 71 F2 08 66 0F EF C1 66 0F EF D3 66 0F 7F 44 24 60 66 0F 7F 54 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_6dad0380 {
    meta:
        author = "Elastic Security"
        id = "6dad0380-7771-4fb9-a7e5-176eeb6fcfd7"
        fingerprint = "ffe022f42e98c9c1eeb3aead0aca9d795200b4b22f89e7f3b03baf96f18c9473"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "628b1cc8ccdbe2ae0d4ef621da047e07e2532d00fe3d4da65f0a0bcab20fb546"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 C1 E6 05 48 01 C6 48 39 F1 74 05 49 89 74 24 08 44 89 E9 48 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e73f501e {
    meta:
        author = "Elastic Security"
        id = "e73f501e-019c-4281-ae93-acde7ad421af"
        fingerprint = "bd9e6f2548c918b2c439a047410b6b239c3993a3dbd85bfd70980c64d11a6c5c"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "2f646ced4d05ba1807f8e08a46ae92ae3eea7199e4a58daf27f9bd0f63108266"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 03 51 8A 92 FF F3 20 01 DE 63 AF 8B 54 73 0A 65 83 64 88 60 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_5e56d076 {
    meta:
        author = "Elastic Security"
        id = "5e56d076-0d6d-4979-8ebc-52607dcdb42d"
        fingerprint = "e9ca9b9faee091afed534b89313d644a52476b4757663e1cdfbcbca379857740"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "32e1cb0369803f817a0c61f25ca410774b4f37882cab966133b4f3e9c74fac09"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 71 18 4C 89 FF FF D0 48 8B 84 24 A0 00 00 00 48 89 43 60 48 8B 84 24 98 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_54357231 {
    meta:
        author = "Elastic Security"
        id = "54357231-23d8-44f5-94d7-71da02a8ba38"
        fingerprint = "8bbba49c863bc3d53903b1a204851dc656f3e3d68d3c8d5a975ed2dc9e797e13"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "388b927b850b388e0a46a6c9a22b733d469e0f93dc053ebd78996e903b25e38a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 F2 06 C5 F9 EB C2 C4 E3 79 16 E0 02 C4 E3 79 16 E2 03 C5 F9 70 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_467c4d46 {
    meta:
        author = "Elastic Security"
        id = "467c4d46-3272-452c-9251-3599d16fc916"
        fingerprint = "cbde94513576fdb7cabf568bd8439f0194d6800373c3735844e26d262c8bc1cc"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "388b927b850b388e0a46a6c9a22b733d469e0f93dc053ebd78996e903b25e38a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 49 8B 77 08 48 21 DE 4C 39 EE 75 CE 66 41 83 7F 1E 04 4C 89 F5 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e0cca9dc {
    meta:
        author = "Elastic Security"
        id = "e0cca9dc-0f3e-42d8-bb43-0625f4f9bfe1"
        fingerprint = "e7bc17ba356774ed10e65c95a8db3b09d3b9be72703e6daa9b601ea820481db7"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "59a1d8aa677739f2edbb8bd34f566b31f19d729b0a115fef2eac8ab1d1acc383"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 24 40 48 8D 94 24 C0 00 00 00 F3 41 0F 6F 01 48 89 7C 24 50 48 89 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_36e404e2 {
    meta:
        author = "Elastic Security"
        id = "36e404e2-be7c-40dc-b861-8ab929cad019"
        fingerprint = "7268b94d67f586ded78ad3a52b23a81fd4edb866fedd0ab1e55997f1bbce4c72"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "59a1d8aa677739f2edbb8bd34f566b31f19d729b0a115fef2eac8ab1d1acc383"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 61 6C 73 65 20 70 6F 73 69 74 69 76 65 29 1B 5B 30 6D 00 44 45 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_947dcc5e {
    meta:
        author = "Elastic Security"
        id = "947dcc5e-be4c-4d31-936f-63d466db2934"
        fingerprint = "f6087a90a9064b505b60a1c53af008b025064f4a823501cae5f00bbe5157d67b"
        creation_date = "2024-04-19"
        last_modified = "2024-06-12"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "7c5a6ac425abe60e8ea5df5dfa8211a7c34a307048b4e677336b735237dcd8fd"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 28 00 00 0A 30 51 9F E5 04 20 94 E5 04 30 A0 E1 38 00 44 E2 00 40 94 E5 00 40 82 E5 04 20 93 E5 04 20 84 E5 0C 20 13 E5 00 30 83 E5 04 00 12 E3 04 30 83 E5 06 00 00 0A 04 10 C2 E3 08 00 12 E3 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_b4c2d007 {
    meta:
        author = "Elastic Security"
        id = "b4c2d007-9464-4b72-ae2d-b0f1aeaa6fca"
        fingerprint = "364fa077b99cd32d790399fd9f06f99ffef19c37487ef8a4fd81bf36988ecaa6"
        creation_date = "2024-04-19"
        last_modified = "2024-06-12"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "e1e518ba226d30869e404b92bfa810bae27c8b1476766934961e80c44e39c738"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FD 03 00 91 F3 53 01 A9 F4 03 00 AA 20 74 40 F9 60 17 00 B4 20 10 42 79 F3 03 01 AA F9 6B 04 A9 40 17 00 34 62 62 40 39 F5 5B 02 A9 26 10 40 39 F7 63 03 A9 63 12 40 B9 FB 73 05 A9 3B A0 03 91 }
    condition:
        all of them
}

