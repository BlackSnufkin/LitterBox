rule Linux_Cryptominer_Camelot_9ac1654b {
    meta:
        author = "Elastic Security"
        id = "9ac1654b-f2f0-4d32-8e2a-be30b3e61bb0"
        fingerprint = "156c60ee17e9b39cb231d5f0703b6e2a7e18247484f35e11d3756a025873c954"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CD 41 C1 CC 0B 31 D1 31 E9 44 89 D5 44 31 CD C1 C9 07 41 89 E8 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_b25398dd {
    meta:
        author = "Elastic Security"
        id = "b25398dd-33cc-4ad8-b943-cd06ff7811fb"
        fingerprint = "6bdcefe93b1c36848b79cdc6b2ff79deb04012a030e5d92e725c87e520c15554"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "6fb3b77be0a66a10124a82f9ec6ad22247d7865a4d26aa49c5d602320318ce3c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 04 76 48 8B 44 07 23 48 33 82 C0 00 00 00 48 89 44 24 50 49 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_6a279f19 {
    meta:
        author = "Elastic Security"
        id = "6a279f19-3c9e-424b-b89e-8807f40b89eb"
        fingerprint = "1c0ead7a7f7232edab86d2ef023c853332254ce1dffe1556c821605c0a83d826"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "5b01f72b2c53db9b8f253bb98c6584581ebd1af1b1aaee62659f54193c269fca"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 F3 89 D6 48 83 EC 30 48 89 E2 64 48 8B 04 25 28 00 00 00 48 89 44 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_4e7945a4 {
    meta:
        author = "Elastic Security"
        id = "4e7945a4-b827-4496-89d8-e63c3141c773"
        fingerprint = "bb2885705404c7d49491ab39fa8f50d85c354a43b4662b948c30635030feee74"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "b7504ce57787956e486d951b4ff78d73807fcc2a7958b172febc6d914e7a23a7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 81 EC A0 00 00 00 48 89 7D F0 48 8B 7D F0 48 89 F8 48 05 80 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_29c1c386 {
    meta:
        author = "Elastic Security"
        id = "29c1c386-c09c-4a58-b454-fc8feb78051d"
        fingerprint = "2ad8d0d00002c969c50fde6482d797d76d60572db5935990649054b5a103c5d1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "fc73bbfb12c64d2f20efa22a6d8d8c5782ef57cb0ca6d844669b262e80db2444"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 65 20 62 72 61 6E 63 68 00 00 00 49 67 6E 6F 72 69 6E 67 20 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_25b63f54 {
    meta:
        author = "Elastic Security"
        id = "25b63f54-8a32-4866-8f90-b2949f5e7539"
        fingerprint = "c0bc4f5fc0ad846a90e214dfca8252bf096463163940930636c1693c7f3833fa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 6F 39 66 41 0F 6F 32 66 4D 0F 7E C3 66 44 0F D4 CB 66 45 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_73e2373e {
    meta:
        author = "Elastic Security"
        id = "73e2373e-75ac-4385-b663-a50423626fc8"
        fingerprint = "6ce73e55565e9119a355b91ec16c2147cc698b1a57cc29be22639b34ba39eea9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "fc73bbfb12c64d2f20efa22a6d8d8c5782ef57cb0ca6d844669b262e80db2444"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 F8 48 83 7D F8 00 74 4D 48 8B 55 80 48 8D 45 A0 48 89 D6 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_b8552fff {
    meta:
        author = "Elastic Security"
        id = "b8552fff-29a9-4e09-810a-b4b52a7a3fb4"
        fingerprint = "d5998e0bf7df96dd21d404658589fb37b405398bd3585275419169b30c72ce62"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "cdd3d567fbcbdd6799afad241ae29acbe4ab549445e5c4fc0678d16e75b40dfa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 18 8B 44 24 1C 8B 50 0C 83 E8 04 8B 0A FF 74 24 28 FF 74 24 28 FF 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_83550472 {
    meta:
        author = "Elastic Security"
        id = "83550472-4c97-4afc-b187-1a7ffc9acbbc"
        fingerprint = "63cf1cf09ad06364e1b1f15774400e0544dbb0f38051fc795b4fc58bd08262d1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "d2d8421ffdcebb7fed00edcf306ec5e86fc30ad3e87d55e85b05bea5dc1f7d63"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FA 48 8D 4A 01 48 D1 E9 48 01 CA 48 29 F8 48 01 C3 49 89 C4 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_8799d8d6 {
    meta:
        author = "Elastic Security"
        id = "8799d8d6-714b-4837-be60-884d78e3b8f3"
        fingerprint = "05c8d7c1d11352f2ec0b5d96a7b2378391ad9f8ae285a1299111aca38352f707"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "4a6d98eae8951e5b9e0a226f1197732d6d14ed45c1b1534d3cdb4413261eb352"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 72 56 66 48 32 37 48 4D 5A 75 6D 74 46 75 4A 72 6D 48 47 38 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_0f7c5375 {
    meta:
        author = "Elastic Security"
        id = "0f7c5375-99dc-4204-833a-9128798ed2e9"
        fingerprint = "53bb31c6ba477ed86e55ce31844055c26d7ab7392d78158d3f236d621181ca10"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "e75be5377ad65abdc69e6c7f9fe17429a98188a217d0ca3a6f40e75c4f0c07e8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 7F 48 89 85 C0 00 00 00 77 08 48 83 85 C8 00 00 00 01 31 F6 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_87639dbd {
    meta:
        author = "Elastic Security"
        id = "87639dbd-da2d-4cf9-a058-16f4620a5a7f"
        fingerprint = "c145df0a671691ef2bf17644ec7c33ebb5826d330ffa35120d4ba9e0cb486282"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "d2d8421ffdcebb7fed00edcf306ec5e86fc30ad3e87d55e85b05bea5dc1f7d63"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 00 48 83 C2 01 48 89 EF 48 89 53 38 FF 50 18 48 8D 7C 24 30 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_cdd631c1 {
    meta:
        author = "Elastic Security"
        id = "cdd631c1-2c03-47dd-b50a-e8c0b9f67271"
        fingerprint = "fa174ac25467ab6e0f11cf1f0a5c6bf653737e9bbdc9411aabeae460a33faa5e"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "91549c171ae7f43c1a85a303be30169932a071b5c2b6cf3f4913f20073c97897"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 5F 5A 4E 35 78 6D 72 69 67 35 50 6F 6F 6C 73 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_209b02dd {
    meta:
        author = "Elastic Security"
        id = "209b02dd-3087-475b-8d28-baa18647685b"
        fingerprint = "5829daea974d581bb49ac08150b63b7b24e6fae68f669b6b7ab48418560894d4"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "60d33d1fdabc6b10f7bb304f4937051a53d63f39613853836e6c4d095343092e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 31 F5 44 0B 5C 24 F4 41 C1 EA 10 44 0B 54 24 }
    condition:
        all of them
}

