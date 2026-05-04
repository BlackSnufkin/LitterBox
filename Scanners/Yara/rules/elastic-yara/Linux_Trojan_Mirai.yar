rule Linux_Trojan_Mirai_268aac0b {
    meta:
        author = "Elastic Security"
        id = "268aac0b-c5c7-4035-8381-4e182de91e32"
        fingerprint = "9c581721bf82af7dc6482a2c41af5fb3404e01c82545c7b2b29230f707014781"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 18 0F B7 44 24 20 8B 54 24 1C 83 F9 01 8B 7E 0C 89 04 24 8B }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d5f2abe2 {
    meta:
        author = "Elastic Security"
        id = "d5f2abe2-511f-474d-9292-39060bbf6feb"
        fingerprint = "475a1c92c0a938196a5a4bca708b338a62119a2adf36cabf7bc99893fee49f2a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c490586fbf90d360cf3b2f9e2dc943809441df3dfd64dadad27fc9f5ee96ec74"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 56 41 89 FE 40 0F B6 FF 41 55 49 89 F5 BE 08 00 00 00 41 54 41 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1cb033f3 {
    meta:
        author = "Elastic Security"
        id = "1cb033f3-68c1-4fe5-9cd1-b5d066c1d86e"
        fingerprint = "49201ab37ff0b5cdfa9b0b34b6faa170bd25f04df51c24b0b558b7534fecc358"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C3 EB 06 8A 46 FF 88 47 FF FF CA 48 FF C7 48 FF C6 83 FA FF }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_fa3ad9d0 {
    meta:
        author = "Elastic Security"
        id = "fa3ad9d0-7c55-4621-90fc-6b154c44a67b"
        fingerprint = "fe93a3552b72b107f95cc5a7e59da64fe84d31df833bf36c81d8f31d8d79d7ca"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CB 08 C1 CB 10 66 C1 CB 08 31 C9 8A 4F 14 D3 E8 01 D8 66 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0cb1699c {
    meta:
        author = "Elastic Security"
        id = "0cb1699c-9a08-4885-aa7f-0f1ee2543cac"
        fingerprint = "6e44c68bba8c9fb53ac85080b9ad765579f027cabfea5055a0bb3a85b8671089"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { DB 8B 4C 24 0C 8B 54 24 08 83 F9 01 76 10 0F B7 02 83 E9 02 83 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_6f021787 {
    meta:
        author = "Elastic Security"
        id = "6f021787-9c2d-4536-bd90-5230c85a8718"
        fingerprint = "33ba39b77e55b1a2624e7846e06b2a820de9a8a581a7eec57e35b3a1636b8b0d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "88183d71359c16d91a3252085ad5a270ad3e196fe431e3019b0810ecfd85ae10"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 D4 66 89 14 01 0F B6 45 D0 48 63 D0 48 89 D0 48 01 C0 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1e0c5ce0 {
    meta:
        author = "Elastic Security"
        id = "1e0c5ce0-3b76-4da4-8bed-2e5036b6ce79"
        fingerprint = "8e45538b59f9c9b8bc49661069044900c8199e487714c715c1b1f970fd528e3b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5b1f95840caebf9721bf318126be27085ec08cf7881ec64a884211a934351c2d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4C 24 54 31 F6 41 B8 04 00 00 00 BA 03 00 00 00 C7 44 24 54 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_22965a6d {
    meta:
        author = "Elastic Security"
        id = "22965a6d-85d3-4f7c-be4a-581044581b77"
        fingerprint = "a34bcba23cde4a2a49ef8192fa2283ce03c75b2d1d08f1fea477932d4b9f5135"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "09c821aa8977f67878f8769f717c792d69436a951bb5ac06ce5052f46da80a48"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E6 4A 64 2B E4 82 D1 E3 F6 5E 88 34 DA 36 30 CE 4E 83 EC F1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_4032ade1 {
    meta:
        author = "Elastic Security"
        id = "4032ade1-4864-4637-ae73-867cd5fb7378"
        fingerprint = "2b150a6571f5a2475d0b4a2ddb75623d6fa1c861f5385a5c42af24db77573480"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "6150fbbefb916583a0e888dee8ed3df8ec197ba7c04f89fb24f31de50226e688"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 0C 67 56 55 4C 06 87 DE B2 C0 79 AE 88 73 79 0C 7E F8 87 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_b14f4c5d {
    meta:
        author = "Elastic Security"
        id = "b14f4c5d-054f-46e6-9fa8-3588f1ef68b7"
        fingerprint = "a70d052918dd2fbc66db241da6438015130f0fb6929229bfe573546fe98da817"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 53 31 DB 8B 4C 24 0C 8B 54 24 08 83 F9 01 76 15 66 8B 02 83 E9 02 25 FF FF 00 00 83 C2 02 01 C3 83 F9 01 77 EB 49 75 05 0F BE 02 01 C3 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_c8385b81 {
    meta:
        author = "Elastic Security"
        id = "c8385b81-0f5b-41c3-94bb-265ede946a84"
        fingerprint = "dfdbd4dbfe16bcf779adb16352d5e57e3950e449e96c10bf33a91efee7c085e5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "3d27736caccdd3199a14ce29d91b1812d1d597a4fa8472698e6df6ef716f5ce9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8D 74 26 00 89 C2 83 ED 04 C1 E2 0B 31 C2 89 F0 C1 E8 13 89 D1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_122ff2e6 {
    meta:
        author = "Elastic Security"
        id = "122ff2e6-56e6-4aa8-a3ec-c19d31eb1f80"
        fingerprint = "3c9ffd7537e30a21eefa6c174f801264b92a85a1bc73e34e6dc9e29f84658348"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c7dd999a033fa3edc1936785b87cd69ce2f5cac5a084ddfaf527a1094e718bc4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 EB 15 89 F0 83 C8 01 EB 03 8B 5B 08 3B 43 04 72 F8 8B 4B 0C 89 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_26cba88c {
    meta:
        author = "Elastic Security"
        id = "26cba88c-7bd4-4fac-b395-04c4745fee43"
        fingerprint = "358dd5d916fec3e1407c490ce0289886985be8fabee49581afbc01dcf941733e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "4b4758bff3dcaa5640e340d27abba5c2e2b02c3c4a582374e183986375e49be8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F6 41 00 42 00 43 00 44 00 45 00 46 00 47 00 48 00 49 00 4A 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_93fc3657 {
    meta:
        author = "Elastic Security"
        id = "93fc3657-fd21-4e93-a728-c084fc0a6a4a"
        fingerprint = "d01a9e85a01fad913ca048b60bda1e5a2762f534e5308132c1d3098ac3f561ee"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 89 44 24 60 89 D1 31 C0 8B 7C 24 28 FC F3 AB 89 D1 8B 7C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_7c88acbc {
    meta:
        author = "Elastic Security"
        id = "7c88acbc-8b98-4508-ac53-ab8af858660d"
        fingerprint = "e2ef1c60e21f18e54694bcfc874094a941e5f61fa6144c5a0e44548dafa315be"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = "[Cobalt][%s][%s][%s][%s]"
    condition:
        all of them
}

rule Linux_Trojan_Mirai_804f8e7c {
    meta:
        author = "Elastic Security"
        id = "804f8e7c-4786-42bc-92e4-c68c24ca530e"
        fingerprint = "1080d8502848d532a0b38861437485d98a41d945acaf3cb676a7a2a2f6793ac6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 31 ED 81 E1 FF 00 00 00 89 4C 24 58 89 EA C6 46 04 00 C1 FA 1F }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a2d2e15a {
    meta:
        author = "Elastic Security"
        id = "a2d2e15a-a2eb-43c6-a43d-094ee9739749"
        fingerprint = "0e57d17f5c0cd876248a32d4c9cbe69b5103899af36e72e4ec3119fa48e68de2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "567c3ce9bbbda760be81c286bfb2252418f551a64ba1189f6c0ec8ec059cee49"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 42 F0 41 83 F8 01 76 5F 44 0F B7 41 10 4C 01 C0 44 8D 42 EE 41 83 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_5946f41b {
    meta:
        author = "Elastic Security"
        id = "5946f41b-594c-4fde-827c-616a99f6fc1b"
        fingerprint = "f28b9b311296fc587eced94ca0d80fc60ee22344e5c38520ab161d9f1273e328"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "f0b6bf8a683f8692973ea8291129c9764269a6739650ec3f9ee50d222df0a38a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 59 08 AA 3A 4C D3 6C 2E 6E F7 24 54 32 7C 61 39 65 21 66 74 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_da4aa3b3 {
    meta:
        author = "Elastic Security"
        id = "da4aa3b3-521d-4fde-b1be-c381d28c701c"
        fingerprint = "8b004abc37f47de6e4ed35284c23db0f6617eec037a71ce92c10aa8efc3bdca5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "dbc246032d432318f23a4c1e5b6fcd787df29da3bf418613f588f758dcd80617"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 D0 C1 E0 03 89 C2 8B 45 A0 01 D0 0F B6 40 14 3C 1F 77 65 8B }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_70ef58f1 {
    meta:
        author = "Elastic Security"
        id = "70ef58f1-ac74-4e33-ae03-e68d1d5a4379"
        fingerprint = "c46eac9185e5f396456004d1e0c42b54a9318e0450f797c55703122cfb8fea89"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 D0 8B 19 01 D8 0F B6 5C 24 10 30 18 89 D0 8B 19 01 D8 0F B6 5C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ea584243 {
    meta:
        author = "Elastic Security"
        id = "ea584243-6ead-4b96-9a5c-5b5dee12fd57"
        fingerprint = "cbcabf4cba48152b3599570ef84503bfb8486db022a2b10df7544d4384023355"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "f363d9bd2132d969cd41e79f29c53ef403da64ca8afc4643084cc50076ddfb47"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C 81 FA }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_564b8eda {
    meta:
        author = "Elastic Security"
        id = "564b8eda-6f0e-45b8-bef6-d61b0f090a36"
        fingerprint = "63a9e43902e7db0b7a20498b5a860e36201bacc407e9e336faca0b7cfbc37819"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "ff04921d7bf9ca01ae33a9fc0743dce9ca250e42a33547c5665b1c9a0b5260ee"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 FE 01 76 12 0F B7 07 83 EE 02 48 83 C7 02 48 01 C1 83 FE 01 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_7e9f85fb {
    meta:
        author = "Elastic Security"
        id = "7e9f85fb-bfc4-4af6-9315-f6e43fefc4ff"
        fingerprint = "ef420ec934e3fd07d5c154a727ed5c4689648eb9ccef494056fed1dea7aa5f9c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "4333e80fd311b28c948bab7fb3f5efb40adda766f1ea4bed96a8db5fe0d80ea1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 85 50 FF FF FF 0F B6 40 04 3C 07 75 79 48 8B 85 50 FF FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3a85a418 {
    meta:
        author = "Elastic Security"
        id = "3a85a418-2bd9-445a-86cb-657ca7edf566"
        fingerprint = "554aff5770bfe8fdeae94f5f5a0fd7f7786340a95633433d8e686af1c25b8cec"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "86a43b39b157f47ab12e9dc1013b4eec0e1792092d4cef2772a21a9bf4fc518a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 D8 66 C1 C8 08 C1 C8 10 66 C1 C8 08 66 83 7C 24 2C FF 89 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_24c5b7d6 {
    meta:
        author = "Elastic Security"
        id = "24c5b7d6-1aa8-4d8e-9983-c7234f57c3de"
        fingerprint = "3411b624f02dd1c7a0e663f1f119c8d5e47a81892bb7c445b7695c605b0b8ee2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "7c2f8ba2d6f1e67d1b4a3a737a449429c322d945d49dafb9e8c66608ab2154c4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 38 1C 80 FA 3E 74 25 80 FA 3A 74 20 80 FA 24 74 1B 80 FA 23 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_99d78950 {
    meta:
        author = "Elastic Security"
        id = "99d78950-ea23-4166-a85a-7a029209f5b1"
        fingerprint = "3008edc4e7a099b64139a77d15ec0e2c3c1b55fc23ab156304571c4d14bc654c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 89 C3 80 BC 04 83 00 00 00 20 0F 94 C0 8D B4 24 83 00 00 00 25 FF 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3fe3c668 {
    meta:
        author = "Elastic Security"
        id = "3fe3c668-89f4-4601-a167-f41bbd984ae5"
        fingerprint = "2a79caea707eb0ecd740106ea4bed2918e7592c1e5ad6050f6f0992cf31ba5ec"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 84 C0 0F 95 C0 48 FF 45 E8 84 C0 75 E9 8B 45 FC C9 C3 55 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_eedfbfc6 {
    meta:
        author = "Elastic Security"
        id = "eedfbfc6-98a4-4817-a0d6-dcb065307f5c"
        fingerprint = "c79058b4a40630cb4142493062318cdfda881259ac95b70d977816f85b82bb36"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "b7342f7437a3a16805a7a8d4a667e0e018584f9a99591413650e05d21d3e6da6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 7C 39 57 52 AC 57 A8 CE A8 8C FC 53 A8 A8 0E 33 C2 AA 38 14 FB 29 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_6d96ae91 {
    meta:
        author = "Elastic Security"
        id = "6d96ae91-9d5c-48f1-928b-1562b120a74d"
        fingerprint = "fdbeaae0a96f3950d19aed497fae3e7a5517db141f53a1a6315b38b1d53d678b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "e3a1d92df6fb566e09c389cfb085126d2ea0f51a776ec099afb8913ef5e96f9b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 00 00 C1 00 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d8779a57 {
    meta:
        author = "Elastic Security"
        id = "d8779a57-c6ee-4627-9eb0-ab9305bd2454"
        fingerprint = "6c7a18cc03cacef5186d4c1f6ce05203cf8914c09798e345b41ce0dcee1ca9a6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c490586fbf90d360cf3b2f9e2dc943809441df3dfd64dadad27fc9f5ee96ec74"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B6 FF 41 89 D0 85 FF 74 29 38 56 08 74 28 48 83 C6 10 31 D2 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3e72e107 {
    meta:
        author = "Elastic Security"
        id = "3e72e107-3647-4afd-a556-3c49dae7eb0c"
        fingerprint = "3bca41fd44e5e9d8cdfb806fbfcaab3cc18baa268985b95e2f6d06ecdb58741a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "57d04035b68950246dd152054e949008dafb810f3705710d09911876cd44aec7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 85 C0 BA FF FF FF FF 74 14 8D 65 F4 5B 5E 5F 89 D0 5D C3 8D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_5c62e6b2 {
    meta:
        author = "Elastic Security"
        id = "5c62e6b2-9f6a-4c6d-b3fc-c6cbc8cf0b4b"
        fingerprint = "39501003c45c89d6a08f71fbf9c442bcc952afc5f1a1eb7b5af2d4b7633698a8"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF C1 83 F9 05 7F 14 48 63 C1 48 89 94 C4 00 01 00 00 FF C6 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_c5430ff9 {
    meta:
        author = "Elastic Security"
        id = "c5430ff9-af40-4653-94c3-4651a5e9331e"
        fingerprint = "a19dcb00fc5553d41978184cc53ef93c36eb9541ea19c6c50496b4e346aaf240"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5676773882a84d0efc220dd7595c4594bc824cbe3eeddfadc00ac3c8e899aa77"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 FC F3 A6 0F 97 C2 0F 92 C0 38 C2 75 29 83 EC 08 8B }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_402adc45 {
    meta:
        author = "Elastic Security"
        id = "402adc45-6279-44a6-b766-24706b0328fe"
        fingerprint = "01b88411c40abc65c24d7a335027888c0cf48ad190dd3fa1b8e17d086a9b80a0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1ae0cd7e5bac967e31771873b4b41a1887abddfcdfcc76fa9149bb2054b03ca4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C3 EB DF 5A 5B 5D 41 5C 41 5D C3 41 57 41 56 41 55 41 54 55 53 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a39dfaa7 {
    meta:
        author = "Elastic Security"
        id = "a39dfaa7-7d2c-4d40-bea5-bbebad522fa4"
        fingerprint = "95d12cb127c088d55fb0090a1cb0af8e0a02944ff56fd18bcb0834b148c17ad7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 6C 72 00 00 50 E8 4E 0C 00 00 EB 0E 5A 58 59 97 60 8A 54 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_e3e6d768 {
    meta:
        author = "Elastic Security"
        id = "e3e6d768-6510-4eb2-a5ec-8cb8eead13f2"
        fingerprint = "ce11f9c038c31440bcdf7f9d194d1a82be5d283b875cc6170a140c398747ff8c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "b505cb26d3ead5a0ef82d2c87a9b352cc0268ef0571f5e28defca7131065545e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 7E 14 48 89 DF 48 63 C8 4C 89 E6 FC F3 A4 41 01 C5 48 89 FB }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_520deeb8 {
    meta:
        author = "Elastic Security"
        id = "520deeb8-cbc0-4225-8d23-adba5e040471"
        fingerprint = "f4dfd1d76e07ff875eedfe0ef4f861bee1e4d8e66d68385f602f29cc35e30cca"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { ED 48 89 44 24 30 44 89 6C 24 10 7E 47 48 89 C1 44 89 E8 44 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_77137320 {
    meta:
        author = "Elastic Security"
        id = "77137320-6c7e-4bb8-81a4-bd422049c309"
        fingerprint = "afeedf7fb287320c70a2889f43bc36a3047528204e1de45c4ac07898187d136b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 24 01 89 C7 31 F6 31 C9 48 89 A4 24 00 01 00 00 EB 1D 80 7A }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a6a81f9c {
    meta:
        author = "Elastic Security"
        id = "a6a81f9c-b43b-4ec3-8b0b-94c1cfee4f08"
        fingerprint = "e1ec5725b75e4bb3eefe34a17ced900a16af9329a07a99f18f88aaef2678bfc1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 57 00 54 43 50 00 47 52 45 00 4B 54 00 73 68 65 6C 6C 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_485c4b13 {
    meta:
        author = "Elastic Security"
        id = "485c4b13-3c7c-47a7-b926-8237cb759ad7"
        fingerprint = "28f3e8982cee2836a59721c88ee0a9159ad6fdfc27c0091927f5286f3a731e9a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 7E 1F 8B 4C 24 4C 01 D1 0F B6 11 88 D0 2C 61 3C 19 77 05 80 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_7146e518 {
    meta:
        author = "Elastic Security"
        id = "7146e518-f6f4-425d-bac8-b31edc0ac559"
        fingerprint = "334ef623a8dadd33594e86caca1c95db060361c65bf366bacb9bc3d93ba90c4f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 85 82 11 79 AF 20 C2 7A 9E 18 6C A9 00 21 E2 6A C6 D5 59 B4 E8 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_6a77af0f {
    meta:
        author = "Elastic Security"
        id = "6a77af0f-31fa-4793-82aa-10b065ba1ec0"
        fingerprint = "4e436f509e7e732e3d0326bcbdde555bba0653213ddf31b43cfdfbe16abb0016"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 31 D1 89 0F 48 83 C7 04 85 F6 7E 3B 44 89 C8 45 89 D1 45 89 C2 41 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_5f7b67b8 {
    meta:
        author = "Elastic Security"
        id = "5f7b67b8-3d7b-48a4-8f03-b6f2c92be92e"
        fingerprint = "6cb5fb0b7c132e9c11ac72da43278025b60810ea3733c9c6d6ca966163185940"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 38 83 CF FF 89 F8 5A 59 5F C3 57 56 83 EC 04 8B 7C 24 10 8B 4C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a3cedc45 {
    meta:
        author = "Elastic Security"
        id = "a3cedc45-962d-44b5-bf0e-67166fa6c1a4"
        fingerprint = "8335e540adfeacdf8f45c9cb36b08fea7a06017bb69aa264dc29647e7ca4a541"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1ae0cd7e5bac967e31771873b4b41a1887abddfcdfcc76fa9149bb2054b03ca4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 2C 48 8B 03 48 83 E0 FE 48 29 C3 48 8B 43 08 48 83 E0 FE 4A 8D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_7d05725e {
    meta:
        author = "Elastic Security"
        id = "7d05725e-db59-42a7-99aa-99de79728126"
        fingerprint = "7fcd34cb7c37836a1fa8eb9375a80da01bda0e98c568422255d83c840acc0714"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 97 00 00 00 89 6C 24 08 89 74 24 04 89 14 24 0F B7 C0 89 44 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_fa48b592 {
    meta:
        author = "Elastic Security"
        id = "fa48b592-8d80-45af-a3e4-232695b8f5dd"
        fingerprint = "8838d2752b310dbf7d12f6cf023244aaff4fdf5b55cf1e3b71843210df0fcf88"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c9e33befeec133720b3ba40bb3cd7f636aad80f72f324c5fe65ac7af271c49ee"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 31 C0 BA 01 00 00 00 B9 01 00 00 00 03 04 24 89 D7 31 D2 F7 F7 0F }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_b9a9d04b {
    meta:
        author = "Elastic Security"
        id = "b9a9d04b-a997-46c4-b893-e89a3813efd3"
        fingerprint = "874249d8ad391be97466c0259ae020cc0564788a6770bb0f07dd0653721f48b1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = "nexuszetaisacrackaddict"
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ab073861 {
    meta:
        author = "Elastic Security"
        id = "ab073861-38df-4a39-ab81-8451b6fab30c"
        fingerprint = "37ab5e3ccc9a91c885bff2b1b612efbde06999e83ff5c5cd330bd3a709a831f5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "175444a9c9ca78565de4b2eabe341f51b55e59dec00090574ee0f1875422cbac"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { AC 00 00 00 54 60 00 00 50 E8 4E 0C 00 00 EB 0E 5A 58 59 97 60 8A 54 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_637f2c04 {
    meta:
        author = "Elastic Security"
        id = "637f2c04-98e4-45aa-b60a-14a96c6cebb7"
        fingerprint = "7af3d573af8b7f8252590a53adda52ecf53bdaf9a86b52ef50702f048e08ba8c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 48 8B 45 E0 0F B6 00 38 C2 0F 95 C0 48 FF 45 E8 48 FF 45 E0 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_aa39fb02 {
    meta:
        author = "Elastic Security"
        id = "aa39fb02-ca7e-4809-ab5d-00e92763f7ec"
        fingerprint = "b136ba6496816ba9737a3eb0e633c28a337511a97505f06e52f37b38599587cb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 DE 8D 40 F1 3C 01 76 D7 80 FA 38 74 D2 80 FA 0A 74 CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0bce98a2 {
    meta:
        author = "Elastic Security"
        id = "0bce98a2-113e-41e1-95c9-9e1852b26142"
        fingerprint = "993d0d2e24152d0fb72cc5d5add395bed26671c3935f73386341398b91cb0e6e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1b20df8df7f84ad29d81ccbe276f49a6488c2214077b13da858656c027531c80"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4B 52 41 00 46 47 44 43 57 4E 56 00 48 57 43 4C 56 47 41 4A }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3a56423b {
    meta:
        author = "Elastic Security"
        id = "3a56423b-c0cf-4483-87e3-552beb40563a"
        fingerprint = "117d6eb47f000c9d475119ca0e6a1b49a91bbbece858758aaa3d7f30d0777d75"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 1C 8B 44 24 20 0F B6 D0 C1 E8 08 89 54 24 24 89 44 24 20 BA 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d18b3463 {
    meta:
        author = "Elastic Security"
        id = "d18b3463-1b5e-49e1-9ae8-1d63a10a1ccc"
        fingerprint = "4b3d3bb65db2cdb768d91c50928081780f206208e952c74f191d8bc481ce19c6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "cd86534d709877ec737ceb016b2a5889d2e3562ffa45a278bc615838c2e9ebc3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { DF 77 95 8D 42 FA 3C 01 76 8E 80 FA 0B 74 89 80 FA 15 74 84 80 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_fe721dc5 {
    meta:
        author = "Elastic Security"
        id = "fe721dc5-c2bc-4fa6-bdbc-589c6e033e6b"
        fingerprint = "ab7f571a3a3f6b50b9e120612b3cc34d654fc824429a2971054ca0d078ecb983"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 18 EB E1 57 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_575f5bc8 {
    meta:
        author = "Elastic Security"
        id = "575f5bc8-b848-4db4-a99c-132d4d2bc8a4"
        fingerprint = "58e22a2acd002b07e1b1c546e8dfe9885d5dfd2092d4044630064078038e314f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5A 56 5B 5B 55 42 44 5E 59 52 44 44 00 5E 73 5E 45 52 54 43 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_449937aa {
    meta:
        author = "Elastic Security"
        id = "449937aa-682a-4906-89ab-80d7127e461e"
        fingerprint = "cf2c6b86830099f039b41aeaafbffedfb8294a1124c499e99a11f48a06cd1dfd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "6f27766534445cffb097c7c52db1fca53b2210c1b10b75594f77c34dc8b994fe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 5B 72 65 73 6F 6C 76 5D 20 46 6F 75 6E 64 20 49 50 20 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_2e3f67a9 {
    meta:
        author = "Elastic Security"
        id = "2e3f67a9-6fd5-4457-a626-3a9015bdb401"
        fingerprint = "6a06815f3d2e5f1a7a67f4264953dbb2e9d14e5f3486b178da845eab5b922d4f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 53 83 EC 04 0F B6 74 24 14 8B 5C 24 18 8B 7C 24 20 0F B6 44 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_01e4a728 {
    meta:
        author = "Elastic Security"
        id = "01e4a728-7c1c-479b-aed0-cb76d64dbb02"
        fingerprint = "d90477364982bdc6cd22079c245d866454475749f762620273091f2fab73c196"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 44 24 23 48 8B 6C 24 28 83 F9 01 4A 8D 14 20 0F B6 02 88 45 08 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_64d5cde2 {
    meta:
        author = "Elastic Security"
        id = "64d5cde2-e4b1-425b-8af3-314a5bf519a9"
        fingerprint = "1a69f91b096816973ce0c2e775bcf2a54734fa8fbbe6ea1ffcf634ce2be41767"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "caf2a8c199156db2f39dbb0a303db56040f615c4410e074ef56be2662752ca9d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 35 7E B3 02 00 D0 02 00 00 07 01 00 00 0E 00 00 00 18 03 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0d73971c {
    meta:
        author = "Elastic Security"
        id = "0d73971c-4253-4e7d-b1e1-20b031197f9e"
        fingerprint = "95279bc45936ca867efb30040354c8ff81de31dccda051cfd40b4fb268c228c5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C2 83 EB 04 C1 E2 0B 31 C2 89 F0 C1 E8 13 89 D1 31 F0 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_82c361d4 {
    meta:
        author = "Elastic Security"
        id = "82c361d4-2adf-48f2-a9be-677676d7451f"
        fingerprint = "a8a4252c6f7006181bdb328d496e0e29522f87e55229147bc6cf4d496f5828fb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "f8dbcf0fc52f0c717c8680cb5171a8c6c395f14fd40a2af75efc9ba5684a5b49"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 23 CB 67 4C 94 11 6E 75 EC A6 76 98 23 CC 80 CF AE 3E A6 0C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ec591e81 {
    meta:
        author = "Elastic Security"
        id = "ec591e81-8594-4317-89b0-0fb4d43e14c1"
        fingerprint = "fe3d305202ca5376be7103d0b40f746fc26f8e442f8337a1e7c6d658b00fc4aa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "7d45a4a128c25f317020b5d042ab893e9875b6ff0ef17482b984f5b3fe87e451"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 22 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0eba3f5a {
    meta:
        author = "Elastic Security"
        id = "0eba3f5a-1aa8-4dc8-9f63-01bc4959792a"
        fingerprint = "c0f4f9a93672bce63c9e3cfc389c73922c1c24a2db7728ad7ebc1d69b4db150f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2e4f89c76dfefd4b2bfd1cf0467ac0324026355723950d12d7ed51195fd998cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C3 55 48 89 E5 48 83 EC 40 48 89 7D C8 89 F0 66 89 45 C4 C7 45 DC 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_e43a8744 {
    meta:
        author = "Elastic Security"
        id = "e43a8744-1c52-4f95-bd16-be6722bc4d1a"
        fingerprint = "e7ead3d1a51f0d7435a6964293a45cb8fadd739afb23dc48c1d81fbc593b23ef"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "f363d9bd2132d969cd41e79f29c53ef403da64ca8afc4643084cc50076ddfb47"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 23 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_6e8e9257 {
    meta:
        author = "Elastic Security"
        id = "6e8e9257-a6d5-407a-a584-4656816a3ddc"
        fingerprint = "4bad14aebb0b8c7aa414f38866baaf1f4b350b2026735de24bcf2014ff4b0a6a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 53 83 EC 04 8B 5C 24 18 8B 7C 24 20 8A 44 24 14 8A 54 24 1C 88 54 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ac253e4f {
    meta:
        author = "Elastic Security"
        id = "ac253e4f-b628-4dd0-91f1-f19099286992"
        fingerprint = "e2eee1f72b8c2dbf68e57b721c481a5cd85296e844059decc3548e7a6dc28fea"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 31 C9 EB 0A 6B C1 0A 0F BE D2 8D 4C 02 D0 8A 17 48 FF C7 8D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_994535c4 {
    meta:
        author = "Elastic Security"
        id = "994535c4-77a6-4cc6-b673-ce120be8d0f4"
        fingerprint = "a3753e29ecf64bef21e062b8dec96ba9066f665919d60976657b0991c55b827b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "376a2771a2a973628e22379b3dbb9a8015c828505bbe18a0c027b5d513c9e90d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 74 07 31 C0 48 FF C3 EB EA FF C0 83 F8 08 75 F4 48 8D 73 03 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a68e498c {
    meta:
        author = "Elastic Security"
        id = "a68e498c-0768-4321-ab65-42dd6ef85323"
        fingerprint = "951c9dfcba531e5112c872395f6c144c4bc8b71c666d2c7d9d8574a23c163883"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 39 D0 7E 25 8B 4C 24 38 01 D1 8A 11 8D 42 9F 3C 19 77 05 8D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_88de437f {
    meta:
        author = "Elastic Security"
        id = "88de437f-9c98-4e1d-96c0-7b433c99886a"
        fingerprint = "c19eb595c2b444a809bef8500c20342c9f46694d3018e268833f9b884133a1ea"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 08 8B 4C 24 04 85 D2 74 0D 31 C0 89 F6 C6 04 08 00 40 39 D0 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_95e0056c {
    meta:
        author = "Elastic Security"
        id = "95e0056c-bc07-42cf-89ab-6c0cde3ccc8a"
        fingerprint = "a2550fdd2625f85050cfe53159858207a79e8337412872aaa7b4627b13cb6c94"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "45f67d4c18abc1bad9a9cc6305983abf3234cd955d2177f1a72c146ced50a380"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 50 46 00 13 10 11 16 17 00 57 51 47 50 00 52 43 51 51 00 43 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_b548632d {
    meta:
        author = "Elastic Security"
        id = "b548632d-7916-444a-aa68-4b3e38251905"
        fingerprint = "8b355e9c1150d43f52e6e9e052eda87ba158041f7b645f4f67c32dd549c09f28"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "639d9d6da22e84fb6b6fc676a1c4cfd74a8ed546ce8661500ab2ef971242df07"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 0B 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_e0cf29e2 {
    meta:
        author = "Elastic Security"
        id = "e0cf29e2-88d7-4aa4-b60a-c24626f2b246"
        fingerprint = "3f124c3c9f124264dfbbcca1e4b4d7cfcf3274170d4bf8966b6559045873948f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 FE 01 76 12 0F B7 07 83 EE 02 48 83 C7 02 48 01 C2 83 FE 01 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1754b331 {
    meta:
        author = "Elastic Security"
        id = "1754b331-5704-43c1-91be-89c7a0dd29a4"
        fingerprint = "35db945d116a4c9264af44a9947a5e831ea655044728dc78770085c7959a678e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "0d89fc59d0de2584af0e4614a1561d1d343faa766edfef27d1ea96790ac7014b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CF 07 66 5F 10 F0 EB 0C 42 0B 2F 0B 0B 43 C1 42 E4 C2 7C 85 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3278f1b8 {
    meta:
        author = "Elastic Security"
        id = "3278f1b8-f208-42c8-a851-d22413f74dea"
        fingerprint = "7e9fc284c9c920ac2752911d6aacbc3c2bf1b053aa35c22d83bab0089290778d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D2 0F B6 C3 C1 E0 10 0F B6 C9 C1 E2 18 09 C2 0F B6 44 24 40 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ab804bb7 {
    meta:
        author = "Elastic Security"
        id = "ab804bb7-57ab-48db-85cc-a6d88de0c84a"
        fingerprint = "b9716aa7be1b0e4c966a25a40521114e33c21c7ec3c4468afc1bf8378dd11932"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8f0cc764729498b4cb9c5446f1a84cde54e828e913dc78faf537004a7df21b20"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4A 75 05 0F BE 11 01 D0 89 C2 0F B7 C0 C1 FA 10 01 C2 89 D0 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_dca3b9b4 {
    meta:
        author = "Elastic Security"
        id = "dca3b9b4-62f3-41ed-a3b3-80dd0990f8c5"
        fingerprint = "b0471831229be1bcbcf6834e2d1a5b85ed66fb612868c2c207fe009ae2a0e799"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "a839437deba6d30e7a22104561e38f60776729199a96a71da3a88a7c7990246a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 45 F4 01 8B 45 F4 3B 45 F0 75 11 48 8B 45 F8 48 2B 45 D8 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ae9d0fa6 {
    meta:
        author = "Elastic Security"
        id = "ae9d0fa6-be06-4656-9b13-8edfc0ee9e71"
        fingerprint = "ca2bf2771844bec95563800d19a35dd230413f8eff0bd44c8ab0b4c596f81bfc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 EC 04 8A 44 24 18 8B 5C 24 14 88 44 24 03 8A 44 24 10 25 FF 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_612b407c {
    meta:
        author = "Elastic Security"
        id = "612b407c-fceb-4a19-8905-2f5b822f62cc"
        fingerprint = "c48c26b1052ef832d4d6a106db186bf20c503bdf38392a1661eb2d3c3ec010cd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "7833bc89778461a9f46cc47a78c67dda48b498ee40b09a80a21e67cb70c6add1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 11 B2 73 45 2B 7A 57 E2 F9 77 A2 23 EC 7C 0C 29 FE 3F B2 DE 28 6C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d5da717f {
    meta:
        author = "Elastic Security"
        id = "d5da717f-3344-41a8-884e-8944172ea370"
        fingerprint = "c3674075a435ef1cd9e568486daa2960450aa7ffa8e5dbf440a50e01803ea2f3"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1f6bcdfc7d1c56228897cd7548266bb0b9a41b913be354036816643ac21b6f66"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 66 83 7C 24 34 FF 66 89 46 2C 0F 85 C2 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d33095d4 {
    meta:
        author = "Elastic Security"
        id = "d33095d4-ea02-4588-9852-7493f6781bb4"
        fingerprint = "20c0faab6aef6e0f15fd34f9bd173547f3195c096eb34c4316144b19d2ab1dc4"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "72326a3a9160e9481dd6fc87159f7ebf8a358f52bf0c17fbc3df80217d032635"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 66 83 7C 24 54 FF 66 89 46 04 0F 85 CB }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_4e2246fb {
    meta:
        author = "Elastic Security"
        id = "4e2246fb-5f9a-4dea-8041-51758920d0b9"
        fingerprint = "23b0cfabc2db26153c02a7dc81e2006b28bfc9667526185b2071b34d2fb073c4"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1f6bcdfc7d1c56228897cd7548266bb0b9a41b913be354036816643ac21b6f66"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 B8 01 00 00 00 31 DB CD 80 EB FA 8D 8B 10 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d5981806 {
    meta:
        author = "Elastic Security"
        id = "d5981806-0db8-4422-ad57-5d1c0f7464c3"
        fingerprint = "b0fd8632505252315ba551bb3680fa8dc51038be17609018bf9d92c3e1c43ede"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "784f2005853b5375efaf3995208e4611b81b8c52f67b6dc139fd9fec7b49d9dc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 3F 00 00 66 83 7C 24 38 FF 66 89 46 04 0F 85 EA }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_c6055dc9 {
    meta:
        author = "Elastic Security"
        id = "c6055dc9-316b-478d-9997-1dbf455cafcc"
        fingerprint = "b95f582edf2504089ddd29ef1a0daf30644b364f3d90ede413a2aa777c205070"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c1718d7fdeef886caa33951e75cbd9139467fa1724605fdf76c8cdb1ec20e024"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 7F 43 80 77 39 CF 7E 09 83 C8 FF 5A 5D 8A 0E }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3b9675fd {
    meta:
        author = "Elastic Security"
        id = "3b9675fd-1fa1-4e15-9472-64cb93315d63"
        fingerprint = "40a154bafa72c5aa0c085ac2b92b5777d1acecfd28d28b15c7229ba5c59435f2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "4ec4bc88156bd51451fdaf0550c21c799c6adacbfc654c8ec634ebca3383bd66"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 78 10 85 C9 75 65 48 8B 8C 24 A0 00 00 00 48 89 48 10 0F B6 4C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1c0d246d {
    meta:
        author = "Elastic Security"
        id = "1c0d246d-dc23-48d6-accb-1e1db1eba49b"
        fingerprint = "b6b6991e016419b1ddf22822ce76401370471f852866f0da25c7b0f4bec530ee"
        creation_date = "2021-04-13"
        last_modified = "2021-09-16"
        description = "Based off community provided sample"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "211cfe9d158c8a6840a53f2d1db2bf94ae689946fffb791eed3acceef7f0e3dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E7 C0 00 51 78 0F 1B FF 8A 7C 18 27 83 2F 85 2E CB 14 50 2E }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ad337d2f {
    meta:
        author = "Elastic Security"
        id = "ad337d2f-d4ac-42a7-9d2e-576fe633fa16"
        fingerprint = "67cbcb8288fe319c3b8f961210748f7cea49c2f64fc2f1f55614d7ed97a86238"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference = "012b717909a8b251ec1e0c284b3c795865a32a1f4b79706d2254a4eb289c30a7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 75 14 80 78 FF 2F 48 8D 40 FF 0F 94 C2 48 39 D8 77 EB 84 D2 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_88a1b067 {
    meta:
        author = "Elastic Security"
        id = "88a1b067-11d5-4128-b763-2d1747c95eef"
        fingerprint = "b32b42975297aed7cef72668ee272a5cfb753dce7813583f0c3ec91e52f8601f"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference = "1a62db02343edda916cbbf463d8e07ec2ad4509fd0f15a5f6946d0ec6c332dd9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 55 89 E5 0F B6 55 08 0F B6 45 0C C1 E2 18 C1 E0 10 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_76bbc4ca {
    meta:
        author = "Elastic Security"
        id = "76bbc4ca-e6da-40f7-8ba6-139ec8393f35"
        fingerprint = "4206c56b538eb1dd97e8ba58c5bab6e21ad22a0f8c11a72f82493c619d22d9b7"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference = "1a9ff86a66d417678c387102932a71fd879972173901c04f3462de0e519c3b51"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 40 2D E9 00 40 A0 E1 28 20 84 E2 0C 00 92 E8 3B F1 FF EB }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0bfc17bd {
    meta:
        author = "Elastic Security"
        id = "0bfc17bd-49bb-4721-9653-0920b631b1de"
        fingerprint = "d67e4e12e74cbd31037fae52cf7bad8d8d5b4240d79449fa1ebf9a271af008e1"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1cdd94f2a1cb2b93134646c171d947e325a498f7a13db021e88c05a4cbb68903"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 24 64 0F CD 48 8D 14 52 41 0F B6 4C D7 14 D3 E8 01 C5 83 7C 24 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_389ee3e9 {
    meta:
        author = "Elastic Security"
        id = "389ee3e9-70c1-4c93-a999-292cf6ff1652"
        fingerprint = "59f2359dc1f41d385d639d157b4cd9fc73d76d8abb7cc09d47632bb4c9a39e6e"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 45 00 EB 2C 8B 4B 04 8B 13 8B 7B 18 8B 01 01 02 8B 02 83 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_cc93863b {
    meta:
        author = "Elastic Security"
        id = "cc93863b-1050-40ba-9d02-5ec9ce6a3a28"
        fingerprint = "f3ecd30f0b511a8e92cfa642409d559e7612c3f57a1659ca46c77aca809a00ac"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C3 57 8B 44 24 0C 8B 4C 24 10 8B 7C 24 08 F3 AA 8B 44 24 08 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_8aa7b5d3 {
    meta:
        author = "Elastic Security"
        id = "8aa7b5d3-e1eb-4b55-b36a-0d3a242c06e9"
        fingerprint = "02a2c18c362df4b1fceb33f3b605586514ba9a00c7afedf71c04fa54d8146444"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 4C 24 14 8B 74 24 0C 8B 5C 24 10 85 C9 74 0D 31 D2 8A 04 1A 88 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_76908c99 {
    meta:
        author = "Elastic Security"
        id = "76908c99-e350-4dbb-9559-27cbe05f55f9"
        fingerprint = "1741b0c2121e3f73bf7e4f505c4661c95753cbf7e0b7a1106dc4ea4d4dd73d6c"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "533a90959bfb337fd7532fb844501fd568f5f4a49998d5d479daf5dfbd01abb2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 64 24 F8 48 89 04 24 48 8B C6 48 8B 34 24 48 87 CF 48 8B 4C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1538ce1a {
    meta:
        author = "Elastic Security"
        id = "1538ce1a-7078-4be3-bd69-7e692a1237f5"
        fingerprint = "f3d82cae74db83b7a49c5ec04d1a95c3b17ab1b935de24ca5c34e9b99db36803"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FD 00 00 00 FD 34 FD FD 04 40 FD 04 FD FD 7E 14 FD 78 14 1F 0F }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_07b1f4f6 {
    meta:
        author = "Elastic Security"
        id = "07b1f4f6-9324-48ab-9086-b738fdaf47c3"
        fingerprint = "bebafc3c8e68b36c04dc9af630b81f9d56939818d448759fdd83067e4c97e87a"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FD 08 FD 5C 24 48 66 FD 07 66 FD 44 24 2E 66 FD FD 08 66 FD 47 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_feaa98ff {
    meta:
        author = "Elastic Security"
        id = "feaa98ff-6cd9-40bb-8c4f-ea7c79b272f3"
        fingerprint = "0bc8ba390a11e205624bc8035b1d1e22337a5179a81d354178fa2546c61cdeb0"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F FD FD FD FD FD FD 7A 03 41 74 5E 42 31 FD FD 6E FD FD FD FD }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3acd6ed4 {
    meta:
        author = "Elastic Security"
        id = "3acd6ed4-6d62-47af-8d80-d5465abce38a"
        fingerprint = "e787989c37c26d4bb79c235150a08bbf3c4c963e2bc000f9a243a09bbf1f59cb"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2644447de8befa1b4fe39b2117d49754718a2f230d6d5f977166386aa88e7b84"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E5 7E 44 4C 89 E3 31 FF 48 C1 E3 05 48 03 5D 38 48 89 2B 44 88 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_eb940856 {
    meta:
        author = "Elastic Security"
        id = "eb940856-60d2-4148-9126-aac79a24828e"
        fingerprint = "01532c6feda3487829ad005232d30fe7dde5e37fd7cecd2bb9586206554c90a7"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fbf814c04234fc95b6a288b62fb9513d6bbad2e601b96db14bb65ab153e65fef"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 84 24 80 00 00 00 31 C9 EB 23 48 89 4C 24 38 48 8D 84 24 C8 00 }
    condition:
        all of them
}

