rule Windows_Generic_MalCert_ec4381c9 {
    meta:
        author = "Elastic Security"
        id = "ec4381c9-abbb-4faa-8655-38204b267a3e"
        fingerprint = "83e27f8dc8dc38dfb4fea9f506065008098a44a6236717ba341f02e23aebbacc"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "6b0ce8e6ccab57ece76302b1c9ab570336f63bae4d11137ccf0b662fa323a457"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 4D 60 69 B5 05 25 63 39 49 C1 2B 22 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_024569d4 {
    meta:
        author = "Elastic Security"
        id = "024569d4-aa57-4aaa-9e93-afea6f73ae3a"
        fingerprint = "c2142515db4cc4f86a0ee389746f4f555e05a2a868596315dfe72dbce4bcce2a"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "fa3614bbfbe3ccdee5262a4ad0ae4808cb0e689cde22eddaf30dd8eb23b0440b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 25 06 C0 C5 BA 74 E2 F6 01 FD 8F D8 F4 4B 79 A1 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_871164db {
    meta:
        author = "Elastic Security"
        id = "871164db-4ca9-4cad-9ef2-70fc20080aea"
        fingerprint = "ee4b1cc91ca7bcff941f449c6264ef166020aca705f5f59ee35e3aa9b8544ede"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "2ef886a8a67509d25708026b2ea18ce3f6e5a2fecd7b43a900e43dddab9a7935"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 0B 35 60 46 7C 36 DE 7E 94 29 E0 A9 78 2D B2 D6 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_101ac60e {
    meta:
        author = "Elastic Security"
        id = "101ac60e-70e0-4946-a6f3-90dac6db2baf"
        fingerprint = "2ce306f3a339649d5536de2cd127f3f7dbadbb0bebcb3dccd1e4bfcde99b4191"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "05c02be58b84139a25c8cd8662efd3a377765a0d69ab206aa6b17e22904ebc9e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 77 28 6A 4C BB 8C 2A D8 CD E8 4A AD }
    condition:
        all of them
}

rule Windows_Generic_MalCert_abeefc63 {
    meta:
        author = "Elastic Security"
        id = "abeefc63-ba3d-47b8-ac9d-68df075f3a4c"
        fingerprint = "e31c13d8f259a557a5afe7db6be2c9b4e5a1c3fadeee81c05f6c589dfe87c2a2"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c070b4fefefe4d3fdce930166f65a43b788eaf24e53bd67d301d920a5c594462"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 41 85 CF D1 37 F9 9E A0 EB 45 46 54 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_234b63fb {
    meta:
        author = "Elastic Security"
        id = "234b63fb-8f9c-41c5-8b74-d145caebf855"
        fingerprint = "40845cbe09195aca9f7e20c5adb421b5c3afb7341d2d8f9f73bdca942e82d9e3"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "bd699b1213d86f2d1d35f79bd74319d24df1c77cdef5c010720dfb290d0c74f2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 51 E1 5E FC 91 6D A7 06 BF E8 47 36 6E 5C AF CB }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ab8661e1 {
    meta:
        author = "Elastic Security"
        id = "ab8661e1-7fc9-49b1-a314-657992fc0961"
        fingerprint = "8838e1f2210f6915622fc694e937cb5b80401b5643352d93dead4478d57c6a47"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5b7aefe3a61be8dbc94b2f8f75ad479a93a04078f0f0b45ba6c86ab7eb12f911"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 08 2B DD E2 74 00 8D CD FF 05 BA 08 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_6926a408 {
    meta:
        author = "Elastic Security"
        id = "6926a408-caf2-4f07-8730-7aa58ff20e11"
        fingerprint = "6dd71678162cce3c9e0dc0646c67c6c6651cd4510e9eb22d7783cb2eef544c65"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "737916b4a5c2efd460eb4bf84dc4d01d505f1c0779a984e5471b2bc71582a545"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 50 57 28 6E 40 33 FC B0 00 00 00 00 55 65 F5 AC }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ff00d21d {
    meta:
        author = "Elastic Security"
        id = "ff00d21d-632f-4a9f-81de-f07d54181156"
        fingerprint = "6ef1037539351e1af3b44235117dab4a15917a5ba0fa23a7ca9b45c354a953be"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "f275e6b5ded3553648a1f231cd4079d30186583be0edeca734b639073ae53854"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 04 4C 17 7A 97 }
        $a2 = "Netgear Inc."
    condition:
        all of them
}

rule Windows_Generic_MalCert_f20eba4e {
    meta:
        author = "Elastic Security"
        id = "f20eba4e-3ef3-41c8-8977-452deec74def"
        fingerprint = "4f564659531d3170dd080cad6d6c27b110925c8b8122d88466efeb0e39e92b23"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "511c9272baf722bddd855a16f1b5ec6fc3229c9dc4ab105abfffb79ecc1814ce"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 0A CC D6 0A D2 B2 ED 55 60 F4 67 DD F4 5C EA 0D }
    condition:
        all of them
}

rule Windows_Generic_MalCert_30719a7d {
    meta:
        author = "Elastic Security"
        id = "30719a7d-7a20-490d-ac45-1a721c313667"
        fingerprint = "085c588bf642cb66db9401a5cc07eb60e527bcf6eb1da443a300fe98b37445a9"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "7822ff888410631fe2844b3c843319e9d135a32b75ecd497c3f91ec68c5b9825"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 79 D0 57 D5 AB 18 35 B2 0E 55 27 FC F1 01 92 CC }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ec2b87b1 {
    meta:
        author = "Elastic Security"
        id = "ec2b87b1-15b1-46ae-b38b-17407eb4e7d1"
        fingerprint = "8c48831c856b7da2b821aad3daf4ecf37e87b3ef8231635df038239531cca4bf"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "eef13758a7f78dfda5386aee61d9ab02efd9057963fd4837cac1a866c8f17e1b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 35 2C 54 2B 8E 0C 2B 4F FE 99 94 E1 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_c9e89da2 {
    meta:
        author = "Elastic Security"
        id = "c9e89da2-9479-4c50-a867-48ae647122d8"
        fingerprint = "c72f85c5fd5090953fde7c4044f8fde2a6e0680757f088ef64bd8fb260f4ed46"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "251f3eecf4f6b846ff595a251bb85fad09f28b654c08d3c76a89ed4cc94197d2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 01 FF 82 F4 00 3A 6F D1 5A B7 A3 EB CA 98 7F 60 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_326bc791 {
    meta:
        author = "Elastic Security"
        id = "326bc791-5edc-423d-bf42-04d9bffb8cc2"
        fingerprint = "314cd245fce2229fe1ec2fc50fdfd524a44957881eae334fc0762578a6564cd7"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "f8b4164773dfabb8058d869f4ae7a6d2741a885a75fbbcc51722c4ba4e145319"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 01 5A 5B AC 49 42 DB EB AB 59 8A B8 90 D9 2C F5 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_e822d2d7 {
    meta:
        author = "Elastic Security"
        id = "e822d2d7-96fd-4aa6-8067-05a193e25df5"
        fingerprint = "66be1218888a8255047920a578918f25bce48f98d422032a81d9cde7f098ddac"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "1acfde9d39095bfb538c30f0523918bd1f2cae83f62009ec0a3a03d54e26d8ca"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 2A 07 4C F0 80 DF CB 55 86 83 23 83 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_cf230984 {
    meta:
        author = "Elastic Security"
        id = "cf230984-5399-4f53-80e7-3c3164ce1c5d"
        fingerprint = "3b22327aeb3fef773758e2eb64016ab9390d8f14167956c38f29441b12423d04"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "746b1ceebc0116b2c1e6c54bd6824b58d289a6067a3d7a53c82d5527414d0aff"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 0B 59 CB 3A 46 C1 6D 81 E8 00 26 DF }
    condition:
        all of them
}

rule Windows_Generic_MalCert_082de32b {
    meta:
        author = "Elastic Security"
        id = "082de32b-7eb7-47af-8fe0-16523ecee53f"
        fingerprint = "4b0e48b4af0d146499c265fc4fab14a02aaedc348e977b88aac2192a70a6d719"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "6a75f271addce817d0350ac7ec7eacc15bfb8bf558284382b4f88bad87606faa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 52 74 D0 11 18 FF EB BD D7 E2 73 5A }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a47f5902 {
    meta:
        author = "Elastic Security"
        id = "a47f5902-d6be-4713-87ca-384cdd012a0b"
        fingerprint = "d1cb1c9167f1f6c04c6c96a1a47e1e4f58148c602f7fbeee80d5c70f3328fd51"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "313d6d6e9ba8e2335689b4993b14e90beba6ed0cf859f842a5d625036703e015"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 37 E2 F1 6D 1C 64 39 E4 52 9D 9E E4 80 93 FA 38 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a318116e {
    meta:
        author = "Elastic Security"
        id = "a318116e-9a9a-48a2-9cab-0c846bc84c22"
        fingerprint = "e62a415b9ca15450e2e5c0ef5bce551adc2379bdd8dd663c97c6e17c930aa480"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "53d60c9bff836ba832c39fecb2d57fffe594dfd0e9149b40f5c9e473bccbf34f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 70 86 6B 58 66 85 F4 F3 9A 5B 47 17 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_d743cb47 {
    meta:
        author = "Elastic Security"
        id = "d743cb47-c046-4d3b-b04d-88e8486d8dbf"
        fingerprint = "be810e0016325fcd7e58aee9ea26062052b56397f1877cf94e7dc94a40a98f17"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "70668430bda8e76026d01964200fdb93ae276e9af15d202613aec97107573c6d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 3C 56 D6 27 7A 99 7F D1 D7 80 87 32 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_21c05181 {
    meta:
        author = "Elastic Security"
        id = "21c05181-7532-449e-a8da-96cd216c5241"
        fingerprint = "87413a7739d8de920c583c5b7ba42409014f4d3f2bd8170a22722d6c9a556cae"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "598d2e71d2aa01e03aeb2ad1ef037ad5489f3bce1e1bde0a3e05d73565f5955b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 20 52 32 B8 64 FC 3D 16 1B 07 33 A9 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_276c83b7 {
    meta:
        author = "Elastic Security"
        id = "276c83b7-60cf-4eb3-8fbd-69169e0479ce"
        fingerprint = "b25ceafeece544b1020c628ba5e5611a29ec7007766dba9aff676fe2394112b6"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "8071c7b74e7ca2769f3746ec8cc007caee65474bb77808b7a84c84f877452605"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 FE F3 86 AC 9C 1D 86 36 CB 37 0C 8C 24 7F 44 FA }
    condition:
        all of them
}

rule Windows_Generic_MalCert_2a46688e {
    meta:
        author = "Elastic Security"
        id = "2a46688e-de35-4db3-b387-57449a85085b"
        fingerprint = "62fc9201fcca418c8574dcdb8723a3d6661450db088f1da5f1ffa9128910f27d"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "d2ed769550844ef52eb6d7b0c8617451076504f823e410ab26ec146dc379935c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 21 52 17 A2 A5 CD 73 2C CE FE 5F 88 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_eb360bb1 {
    meta:
        author = "Elastic Security"
        id = "eb360bb1-bb05-4a0f-8e79-2bd9303b7790"
        fingerprint = "e463fe324a2d5280c0063d4279eecea1a425b88d392f6a8c9d95d14f68ba4fd5"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "09003df4deacc194a94c0def0f5aa8a3a8d612ea68d5e6b4b4c5162f208886e0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 4C 03 54 CE 17 E2 C3 64 2C 3D 06 4C }
    condition:
        all of them
}

rule Windows_Generic_MalCert_5f0656b2 {
    meta:
        author = "Elastic Security"
        id = "5f0656b2-cb2d-411a-90c9-d34f5d443b8c"
        fingerprint = "46e7adc1d0ca05f4dc26088246eeda22b32bd263b831a6f2ff648cf3fd870171"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c35a34aade5c7ac67339549287938171026921c391a3630794ac1393fb829e3a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 A2 25 3A EB 5B 0F F1 AE CB FD 41 2C 18 CC F0 7A }
    condition:
        all of them
}

rule Windows_Generic_MalCert_59ff12f8 {
    meta:
        author = "Elastic Security"
        id = "59ff12f8-eac5-47bc-a168-f2db92d56698"
        fingerprint = "b12bba9e0ef3d0bea8e73f6e8773db0a9545b8fd144e51eee3e273cca8962ada"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "f645d0f75ce7f1256c64cd7c52fbd2cc4cafb7ae1b30c39e73907fa01b8079da"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 74 67 20 93 D7 30 4A 14 8F 79 47 AD ED F8 99 86 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_c3d5b526 {
    meta:
        author = "Elastic Security"
        id = "c3d5b526-0e8e-46b1-904d-286cf92319b3"
        fingerprint = "8ab1bbde25f8cd732576aee2bc4763044b622fbad9c81470fda28eaedcf3cd65"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "06497b526cebbfab81e7e0d55118007d80aa84099d99ee5858c822a616ad48a1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 04 DE 74 F8 06 A1 C7 F9 A3 26 F5 83 72 F5 65 42 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_11e18261 {
    meta:
        author = "Elastic Security"
        id = "11e18261-3d8b-482b-ba45-409877bd1392"
        fingerprint = "8eec08fb6a59ba054a2a10c8200877ee37b9949dfc6b6ff20801aafad8dae1b6"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "249b1bb49496b2db3b4e7e24de90c55deeba21fe328909a7d6fae1533d92ce9a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 2D 4C 7F 95 4E 56 1C 98 42 F9 B7 D6 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_9262df80 {
    meta:
        author = "Elastic Security"
        id = "9262df80-4e82-43e2-b21f-e509aced0caf"
        fingerprint = "4fdb73a01e709bb48baf79c91e0eb8d212d8ef213b18666f738df71b5e24a199"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "86e966dacad8d808ba568d9dc53eeffb4e8848fa8eb9516e97c13bed8317b814"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 51 09 AE 83 71 B0 50 7A 4D 72 42 5C }
    condition:
        all of them
}

rule Windows_Generic_MalCert_72de26c5 {
    meta:
        author = "Elastic Security"
        id = "72de26c5-b6bf-49f5-84d4-5cf9ec8c673d"
        fingerprint = "fd9564616cd9609c1c01dd6d903aa64a41846664eed9f964a8a8e6d4eb37dca8"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e74c5cb1bbea30e7abfd292ab134936bb8cd335c52f4fce4bb3994bd6e5024f4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 9D F8 93 43 AD D6 99 DD C9 8F CD 37 67 DA 5F 84 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_7f40a1ba {
    meta:
        author = "Elastic Security"
        id = "7f40a1ba-3fab-43fc-8581-6628065549ac"
        fingerprint = "5d3bde9de4418f94ea3395593e62f2643315ea9f078208d0481a963ff2d37e96"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "88eb72267896a9db69457a9400979772413f3208a41e6cf059c442de719bf98f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 DC C8 1E F1 94 27 B6 B6 2B 71 7E 6E 92 EC 28 13 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a775b53a {
    meta:
        author = "Elastic Security"
        id = "a775b53a-ff41-4377-9c71-2cca9ce02048"
        fingerprint = "23cd01190ed48bf05d69e92b3a00fce7f008ea7f2b5f3d2ee860ffb6a7a45589"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "d38fce27eafc1a8eb4c83cd043fe2494e5c9a4939ff3a2784ca43beb8839bb3a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 28 E8 92 43 4E 59 E2 52 41 3D 3E 0E }
    condition:
        all of them
}

rule Windows_Generic_MalCert_5bcffcb2 {
    meta:
        author = "Elastic Security"
        id = "5bcffcb2-58ec-44d8-9838-3b14090e829f"
        fingerprint = "d40cf9ef781f11f9acb279180a2add28e750a3233a175c4ae538c4702365be47"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5d1aed7bb03d8ea5ba695916d57d64dfdf4b02a763360eb9ccbf407dea21946a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 6E 88 9B B3 B7 F7 19 4B 67 4C 6A 03 35 A6 08 E0 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_37d465f6 {
    meta:
        author = "Elastic Security"
        id = "37d465f6-e3ee-4984-ae4c-02f5f0287723"
        fingerprint = "59ff0f15adffc730d24d107ae1afe047c22376d117b018356b85c21049cf7d3d"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "381e6c630aaf5ca69f01713be8ac29b11869c8e6af28359e6933407854f086ba"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 22 A9 7A E3 EB EA 8C 98 81 6E 1E 5E }
    condition:
        all of them
}

rule Windows_Generic_MalCert_58979ccd {
    meta:
        author = "Elastic Security"
        id = "58979ccd-b83e-4708-b84f-314bbc26f103"
        fingerprint = "e40ea37edb795ef835748eb15d4eb5c66b8f80771ccbd197a7ee3df4520344de"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "12bf973b503296da400fd6f9e3a4c688f14d56ce82ffcfa9edddd7e4b6b93ba9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 21 40 69 1D DE 2D 71 48 85 84 15 D5 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_8d94d2bb {
    meta:
        author = "Elastic Security"
        id = "8d94d2bb-5ee1-4aa0-bae5-c5d91180a08c"
        fingerprint = "e41f27f4ca41b49d8dca2beb3b3eba6d7fa173e574d7a74b7f20801c383a4a8a"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "7250c63c0035065eeae6757854fa2ac3357bab9672c93b77672abf7b6f45920a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 49 7E 77 B2 0D 07 E6 37 B1 3B BA 63 54 BB 86 CF }
    condition:
        all of them
}

rule Windows_Generic_MalCert_2b11268a {
    meta:
        author = "Elastic Security"
        id = "2b11268a-566f-48ad-9a96-dc075a02297b"
        fingerprint = "027c2fcf99ce15c2707505d0939b3826342cce9614dba5073db1c4a68fe39f99"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "4a13f40561173347308fa4da0767af4244e899077b6e609805d61742fdea5363"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 0F 1D 3B 26 EA 4F FB F7 73 10 2C 4E D8 A9 8D 70 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_548079e8 {
    meta:
        author = "Elastic Security"
        id = "548079e8-2f91-42f4-8aed-edfc2110ce75"
        fingerprint = "7aade63c4d26f4833d3bb5fd0ce524dae4606caf20ed379f55d61669c32f004b"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "83679dfd6331a0a0d829c0f3aed5112b69a7024ff1ceebf7179ba5c2b4d21fc5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 30 13 85 AA 36 FA E6 35 E7 4B B8 8E }
    condition:
        all of them
}

rule Windows_Generic_MalCert_c3391d33 {
    meta:
        author = "Elastic Security"
        id = "c3391d33-dc53-4fe8-9e83-a72c978d8aff"
        fingerprint = "9211b30243899416df9362898c034ee81f674b09e203db2c47f8044af5d18d6a"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "d0a18627b9cef78997764ee22ece46e76c6f8be01d309d00dff6ca8b56252648"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 8D AD E4 39 C4 A8 9B 11 48 12 34 B0 B5 0F F6 6F }
    condition:
        all of them
}

rule Windows_Generic_MalCert_1abaf391 {
    meta:
        author = "Elastic Security"
        id = "1abaf391-b148-4d56-b5c5-2d78ef6e98cf"
        fingerprint = "59f04af52c1060795286dd7e229cf3cbfd81f38d8db52eeb417792bd73636e1d"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "37c903910f91654c1a68751cd3b4dd6adc1fdd3477bfb576081b2672be39f3e9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 6A 0D 76 08 17 D8 72 18 99 B4 FB CE F1 56 9D F1 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_32ae7aa7 {
    meta:
        author = "Elastic Security"
        id = "32ae7aa7-c196-44de-be7c-69ee823c9bac"
        fingerprint = "e5377c045b7c445defe35fed431bf735671ae9105ee191e3b55b81704cc35742"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c608a717ff6d907eef8c83512644561d3e18863d42a0f80c778d254d2dcd58aa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 F5 BE 3D 05 57 49 9E 00 6E 00 EF 05 5E 79 19 3E }
    condition:
        all of them
}

rule Windows_Generic_MalCert_f11721e1 {
    meta:
        author = "Elastic Security"
        id = "f11721e1-fbcd-40e3-b060-0f7c82da3cdb"
        fingerprint = "eed60c6691c2a82fd6f8bc41f7f89b939d0b90f9ad940ef6111647f0581aeb75"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "42b0c02bc403c0109d79938f70e33deea25109036c2108e248374917fa22f4a9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 01 F5 2E 57 80 3C C7 22 5D 45 43 70 34 2B 2B C7 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_6753855f {
    meta:
        author = "Elastic Security"
        id = "6753855f-bb08-4c25-a023-6abe63f6f678"
        fingerprint = "9b9bc569ad0c91f8fe94a31074f718919caa4f92e7fe491ab66a18973cdc2a42"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "bdad526c2010c6dfeb413ecd4972d5681104c1cf667fef1b1e4778ca7d96ec35"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 74 26 D2 1D 23 94 D2 EB 72 25 A7 FF C7 EE 36 BE }
    condition:
        all of them
}

rule Windows_Generic_MalCert_0c9007f3 {
    meta:
        author = "Elastic Security"
        id = "0c9007f3-e70c-4fda-b00d-3606b3ed9e5f"
        fingerprint = "2805811562cd1fa87d4dd5e0a65f92bf3f7404e0487f8b6abe56e8a3674296c4"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e4fcfb24360d755e8d4ba198780eed06c0ae94bec415e034d121ac7980d1f6a4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 01 C7 B2 3C FC 00 7A 6C A9 4A BD 7D B7 5E BC 5D }
    condition:
        all of them
}

rule Windows_Generic_MalCert_10d5a0d2 {
    meta:
        author = "Elastic Security"
        id = "10d5a0d2-cdc8-4ebd-9fe9-9a3fd7e6bf1b"
        fingerprint = "cc199dcb5ca8e6f46cf5b40ca4331f7907d871472fca5aec0f3a9188da3712f8"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c974933dd65a10d51f07f1c1bbd034e1357193fa70cf51d3cbe03f8752aa0594"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 0A 7F 68 D7 A3 C7 8A 2A 05 25 EF 97 37 EA B8 81 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_6606e2be {
    meta:
        author = "Elastic Security"
        id = "6606e2be-4503-4f52-b2b6-0b7e190acc8e"
        fingerprint = "4f95a8af6dc00c731c2f64e6030d6e86169963a8fa969d8dd7d7574b91733068"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c1fa31b49157e684fb05494dcf0db72d0133c1d433cb64dc8f6914343f1e6d98"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 83 23 A1 C8 0A 83 EA 88 6F C3 58 08 97 90 39 F7 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_0dece90a {
    meta:
        author = "Elastic Security"
        id = "0dece90a-6870-4436-a456-6798a7b9b7b1"
        fingerprint = "6fd4830173029476f19e558cfcd154dca5adfb637606e6f8da1fe30c0fcddeaf"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "2bc61416837f467bb8560d3a39b14d755f1c9f003254e74cc635e8ff6a00626a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 38 7C 94 76 E2 83 20 26 45 94 84 63 17 D4 65 40 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_18a6f221 {
    meta:
        author = "Elastic Security"
        id = "18a6f221-f688-44a1-a964-1834fb650315"
        fingerprint = "039d864425d19dbd5ad3c36e2a44ae525cc767b7510be5f892e7435759212ce6"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c2614d4f0aeadbdf1cc6efbe9116f7e80393eb560e7cc96f5f0c2300f002d806"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 5D 02 53 3E 72 14 B0 42 D0 2D C0 FB D0 B7 C0 74 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_81098b3c {
    meta:
        author = "Elastic Security"
        id = "81098b3c-aba7-4838-be76-0eb632c7ae1e"
        fingerprint = "d4a67c7f5209e243acc72b5e6baf06b5aa174aa1fe90109941df1c3a9b892ffd"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "dc2358df8e7562b826da179aad111f0fdd461a56470f1bb3c72b25c53c164751"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 11 7E 18 46 AC 13 0D C4 FA 8F 3E 17 9B 5F A3 C9 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_108e8774 {
    meta:
        author = "Elastic Security"
        id = "108e8774-ada3-4319-b713-1213eed8967e"
        fingerprint = "8d7dce4e3474faddfb6dbbd0d706162aed7244ac45d631194eb9be68a5318d06"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "ab21d23f3f642b1d4559df845052d50adce1e0bcc9a0fb88042e72f2791c3a30"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 0D E6 76 A4 C5 AF 15 BF B3 77 1C 14 2A CD A8 FD }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a8d852d0 {
    meta:
        author = "Elastic Security"
        id = "a8d852d0-5fda-4a82-8eb7-5363e44f4fbb"
        fingerprint = "be9cfa1d71fc603e0918a7acfba1b1114bfb1a4c1b717da246722de216762cda"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "ce7dfe11133790e7d123fd7ae1bf7412868f045cbe4a0631a2c7b5ba7225113b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 30 EE 7D 2A 15 85 FA CB E9 3A 8F 0E F8 60 F4 6F }
    condition:
        all of them
}

rule Windows_Generic_MalCert_70d7fab0 {
    meta:
        author = "Elastic Security"
        id = "70d7fab0-e626-4f25-964f-b96791408648"
        fingerprint = "e3b25285539c2cf9bc8f9ff596d1df23e6b0fbfe18c1ed6adf883ad23d1fde08"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c3ef67ddf94f795f7ba18e0e6afc504edbd8ed382699bec299cb1efed9a1788a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 34 9C 35 32 E8 6E 9E 1B 77 CB CF 7F 12 D0 5C AF }
    condition:
        all of them
}

rule Windows_Generic_MalCert_17a7e895 {
    meta:
        author = "Elastic Security"
        id = "17a7e895-02fd-41d4-a4c1-617092cecfeb"
        fingerprint = "f16c6eec08a4fa4018a26fd9dd62b12335091e77ae32610becc5f584fab877ef"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5058a3469d589bdf9279a128db92c792c9aaa6c041aa20f07c4c090ab2152efb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 6F EE 7E 57 96 71 E0 C3 36 CC 10 DD 54 1D C6 98 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_c14990fa {
    meta:
        author = "Elastic Security"
        id = "c14990fa-a441-4e0a-a05a-305abf46a891"
        fingerprint = "16703bc45d5fb7c18b6195483c611878c32fc0a853151ef0a4e75dadaee9b231"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "ce4498bb0e9d8ff33ec55a521c0ba64c7d5ea8c45927496109a42dfcaf4b9ce4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 08 3F 4C 45 67 8D 2C 9C 7E A1 06 C9 00 03 B6 13 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_35a7e8aa {
    meta:
        author = "Elastic Security"
        id = "35a7e8aa-2081-417d-be44-419fc29b70c4"
        fingerprint = "7ec3106a9323a5e2542ffb31b5fe61e274d5d1179867b897e16c453f95bde959"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "cfb5cb22b2b882d620507a88942a4bfe66fd65082b918b1b9a6699fd56ac5a9d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 50 5F 39 51 5D A5 58 18 23 24 C2 CA }
    condition:
        all of them
}

rule Windows_Generic_MalCert_09dd7d76 {
    meta:
        author = "Elastic Security"
        id = "09dd7d76-7fb5-4e6a-8d26-5cc8b350d56c"
        fingerprint = "43174658c61a70035102d1bd59c887f743532ee15ba6a3099d59d085b2a418f8"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "501f636706a737a1186d37a8656b488957a4371b2dd7fcc77f13d5530278719e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 02 D3 48 95 65 F0 54 1F 0A EC 61 84 A4 98 1D 81 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ad55864e {
    meta:
        author = "Elastic Security"
        id = "ad55864e-ce44-436d-93dc-fdf6217a6897"
        fingerprint = "498e32f7e71b9d615e481ce7070e59c6d051c6dd753331e0087b54ee4ffc3919"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "654636d8d996e7aa93e93581f595bf63d32a3fd18c6b84d5c3b31de113fc1740"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 23 10 78 28 3B AC 1A 1A 90 F6 42 02 E8 41 77 AD }
    condition:
        all of them
}

rule Windows_Generic_MalCert_599b3a08 {
    meta:
        author = "Elastic Security"
        id = "599b3a08-264e-4b9f-bfaf-73564de051bc"
        fingerprint = "633b264883a6bfbfac9c226b46e453ebac2881c922853194f64ba7c0e232f42d"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5a1b32b077d39a9bfae88dca7a9e75be5a1e6ace2d3ecb8fc259fdae67d848a1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 2D B9 F8 38 04 C0 78 54 A7 5A B0 8A }
    condition:
        all of them
}

rule Windows_Generic_MalCert_724bed8d {
    meta:
        author = "Elastic Security"
        id = "724bed8d-6230-4184-a148-e3960a23fe52"
        fingerprint = "db56343a197d81ae24f26695e4d1d07a9defeb9f571a3b5070b9ee18aedd4a9e"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "850c3e89c9d98b978e03a837eb24e48ed85b495ca486660016f51f3f41712611"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 0E EB 82 9E EB 4B 17 CB 6C ED 4F 42 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_95327249 {
    meta:
        author = "Elastic Security"
        id = "95327249-cdba-4f30-9d2f-55fc948c0c71"
        fingerprint = "c80085c0edf45b4dbc88d9426d669aa487a4f28ec2f82334217eb7213631c26c"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e99a5e18f6772adaef7d0f8fb13de41eb2c25f25e292c2ea278a0b473642c7eb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 72 BC D4 DE 0F 46 24 38 EF 7A 30 6B 0F 98 E6 68 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_fe1dfef0 {
    meta:
        author = "Elastic Security"
        id = "fe1dfef0-9c56-4e1a-94af-9de1d9d3bce6"
        fingerprint = "ae5565a43abd0c174ac1afb55b7f082dc2b674327b362941374ec2fd099888c1"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "0c9d7c08f2a74189672a32b4988f19cab6280c82a4c4949fb00370dae8c4b427"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 3E A9 D7 D2 B4 B7 4F 29 56 9F 50 6A 64 D5 CC 2A }
    condition:
        all of them
}

rule Windows_Generic_MalCert_726cc1c1 {
    meta:
        author = "Elastic Security"
        id = "726cc1c1-a331-48d5-9209-1b2c5bd1dee0"
        fingerprint = "2f8123b6d0373bf2a2b4351476e9c1339479f83b822c52dd38fa28cf5acf0f56"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "77e103eaffea71d35b1d06d64fdbe546261e95d6360b608e1688c4c437f4da5e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 6E 13 E3 2B CD 62 7A 1D 6C 39 EA 1F 17 46 76 3C }
    condition:
        all of them
}

rule Windows_Generic_MalCert_7749cda8 {
    meta:
        author = "Elastic Security"
        id = "7749cda8-9351-4149-92f8-bebf35b891b6"
        fingerprint = "82adbaa79a1a2e966593692c9d1e9c2ee103d306f675596bcf1c58a59208756f"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e0f9e51835788efa869e932aab139241e0363f6b44fe1c6c230cc26b83701b65"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 6D 30 BD 4D AC 27 22 DE D1 22 24 7C 01 28 6F B1 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_344b6b05 {
    meta:
        author = "Elastic Security"
        id = "344b6b05-6ab1-4a2d-babf-a92fb2dcdefc"
        fingerprint = "41cce85ad5a20851aa5a74d5ed8b983fb28e8967c467a9faee6d517289a909ec"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "4d91a7e24ae7fc3d6e5423c0008707e4e94b0bd3cef153639ba4ec90d61f3c98"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 02 0E B5 27 BA C0 10 99 59 3E 2E A9 02 E3 97 CB }
    condition:
        all of them
}

rule Windows_Generic_MalCert_8228dd5b {
    meta:
        author = "Elastic Security"
        id = "8228dd5b-5ebe-430e-9dcf-5d3abb65c04b"
        fingerprint = "c59df76db61746239de1e750f4e456ae6d0af488550ea05aeb0b2d4a45ffedfd"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "82a6cd7d7e01b7bd2a1c2fc990c9d81a0e09fcef26a28039d2f222e9891bfeff"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 37 E3 20 53 B0 0D 56 23 68 28 E3 D9 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_d1751a98 {
    meta:
        author = "Elastic Security"
        id = "d1751a98-27f5-4a5d-bc73-b6bfebe37c0f"
        fingerprint = "34744efb4a21e8b22ecb3cdced7746b216cb511899b9fa25e7e81438c2a5b9e1"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "9959fc6e686d668f8e5e2f3935b6e8c86b547150acaaf8d9687de4fa4d1c937c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 7D 2C 9D 9D EE F3 AA C2 1C 89 59 76 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_578f96d1 {
    meta:
        author = "Elastic Security"
        id = "578f96d1-7dba-4199-ac35-8726af705230"
        fingerprint = "357041128d835a1af6b345988e52bb19d39bb5654b81587574a50fca2cfdc25a"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "eeb8cb6bc1340b2fa84a2d79ae68c001e05caae3be5c446220dcef5da9579d06"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 C0 E2 8F 6B F3 D8 D0 CC 00 30 6D F9 02 D6 EC 0F }
    condition:
        all of them
}

rule Windows_Generic_MalCert_04e5ae93 {
    meta:
        author = "Elastic Security"
        id = "04e5ae93-eb6e-4d2c-8fdb-b55863432ef5"
        fingerprint = "dc12697fcfea799f10356c0306fa5d7587b7f03b893990be6bb854ddd11554fb"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "1a983e597abdb37653baba58de85bb8e55c6f20aa6bcbd7420b9d14dca586bb7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 0A 43 AC E6 5F 1C EC 7B 0B 10 8D 80 E6 AB A4 BB }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a196f680 {
    meta:
        author = "Elastic Security"
        id = "a196f680-63d3-4cae-94fa-c9a56b782ef8"
        fingerprint = "81f1b0be9b876c7f729d810c9a51777147fdf251a55cd91bee3bf304ec595ad9"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "45fdcd215d2dec931b4136c3b6f4807d53db7a0e1466bbb1afc9d68e872053d3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 2E DD 68 6F FF 3B 20 4C C4 23 16 73 FA CE AC 92 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_21673599 {
    meta:
        author = "Elastic Security"
        id = "21673599-68e5-4a74-ba77-2d2356561caa"
        fingerprint = "813227294fe904a8073a0a2f8bab534c73def88d46d6db5d8db3c27484160bfb"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "804641f152a3e6994e05e316224a5c8f790a2de5681dd78fa85674152e74677a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 1B 3C 13 05 D4 95 D4 9D 68 C7 C0 18 58 3F 25 31 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_321cda6e {
    meta:
        author = "Elastic Security"
        id = "321cda6e-ea2a-4c4b-b660-0245d24858db"
        fingerprint = "7f1f8511b57aa774518a16c47b708b53b828839beff6f445481d783abf7b31f7"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "567115a08d2eebcbdea89d83dd9a297020c360b3f99117b990eb3fe95501acc2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 B7 D1 97 55 1A 90 91 8E C0 B3 20 F6 DA 64 B3 0D }
    condition:
        all of them
}

rule Windows_Generic_MalCert_1c42f7ff {
    meta:
        author = "Elastic Security"
        id = "1c42f7ff-d20b-46a9-a055-b386b59e7e02"
        fingerprint = "5007c14fac7a4aedd5b430d9d800a1fd50cd3eed99ccaf6382f4539bcad1ad2a"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "1618bb5c1d7874a4083ab40eed1106ec24679a64e564752594964a998eb93dfd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 3C C9 EF 0D FC 14 DB 49 96 6F 02 99 8B 69 32 FB }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ae04906b {
    meta:
        author = "Elastic Security"
        id = "ae04906b-3731-4138-ba1a-f4f21033fcc6"
        fingerprint = "550ed59799b77be3c5c9f8d6edefb98f79ba4d148c553ce7138c45e0017a0646"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e115cd3f7f9fb0d34d8ddb909da419a93ff441fd0c6a787afe9c130b03f6ff5e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 02 68 2C EB 56 82 17 E7 B0 DE 48 94 25 B0 D3 C2 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_cd89378b {
    meta:
        author = "Elastic Security"
        id = "cd89378b-1915-43b5-8dd1-063c8634c5ba"
        fingerprint = "18f77b670ba5e9f9e188f158ae3f0b586e850e956b73d024de0c18fb2cc48b68"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "763a4ca9f7ae1b026e87fe1336530edc308c5e23c4b3ef21741adc553eb4b106"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 65 98 E9 51 40 7E 30 11 49 D5 60 EA }
    condition:
        all of them
}

rule Windows_Generic_MalCert_401d2001 {
    meta:
        author = "Elastic Security"
        id = "401d2001-83bd-4575-bb8c-ed7d6fd1288d"
        fingerprint = "c40d33db3adfb1bcb96c58ada22b0380b259d43eeedba1e7cd8bb551ab5c5072"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "6dae04b373b1642e77163a392a14101c05f95f45445f33a171232fa8c921e3fc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 4A CE 35 43 66 56 43 D3 AF 3E AD E4 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_b5f08eaf {
    meta:
        author = "Elastic Security"
        id = "b5f08eaf-9a9a-4144-8c5e-b17fddcbcfba"
        fingerprint = "95beb777140dd964880c0db5839a7437f68a8ca11a0eceeb0aa1cb99841d33e9"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "553e275198061d8c0d35ce89ac083909f12091ed761b8977700548bc968b137a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 63 1A 2A 12 F9 3A A1 2F 79 34 D0 7A 16 A6 54 16 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_d8ebed26 {
    meta:
        author = "Elastic Security"
        id = "d8ebed26-88e6-4360-864b-b43a4658c36e"
        fingerprint = "a02002ea866f7794bfa15855745400385f198a8b96f19bad8dce7c263b6214ad"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "51d03995f68aa54f065b4d23961de01392f9d584740932f6a32312ae2ff34304"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 79 E1 8F 9B 4E 7C AC 3F A1 1E B5 DF F6 A0 51 E0 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_50108ec0 {
    meta:
        author = "Elastic Security"
        id = "50108ec0-956e-4557-a789-80ac894393cd"
        fingerprint = "080c8cc20f5738cab8969b905a3608ec18233f28a55ef4903e11bf7247dfccd0"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "53091c881ecff5baae1e998a15178d8e9da8f0dcd896d036a82799de5fbe605f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 12 11 21 C4 46 16 E3 C6 35 CF 29 3F 8B E9 DC AB 68 5E 6B }
    condition:
        all of them
}

rule Windows_Generic_MalCert_24178164 {
    meta:
        author = "Elastic Security"
        id = "24178164-6a9d-43b5-8b5d-372e17a87e4d"
        fingerprint = "119d5b11a5d7577074a7f52b6b7cedc2c6323778be13e2321021a0fbf6200cea"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "2074099eb6b722d430cbd953ec452984acb84e04c23ddf7e5c9393f906fd910d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 34 DE F8 02 47 9C 8F D6 3C 6A B6 A9 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ea0f93ba {
    meta:
        author = "Elastic Security"
        id = "ea0f93ba-c140-4684-a07d-ef16e70a625c"
        fingerprint = "d75056b8912163520ceeba6ea328a9bf203a1d1b5690fcc0ed30903f23c9f632"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "8143a7df9e65ecc19d5f5e19cdb210675fa16a940382c053724420f2bae4c8bd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 4D B8 E2 54 19 B9 6C 60 FE E8 65 C7 01 B6 2D EF }
    condition:
        all of them
}

rule Windows_Generic_MalCert_08e6d68d {
    meta:
        author = "Elastic Security"
        id = "08e6d68d-2316-4060-9739-c4376906e0f8"
        fingerprint = "f463b04d044f8b58fdc77541aa3655138cdae6ad4ea460bb293c37826968da66"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "19d900ffefd8639dee4d351404e06f47852771e8d2544515776cc1abec4dcecc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 40 CE 44 CE DB 44 70 A1 40 31 F6 E1 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_33d0a7b5 {
    meta:
        author = "Elastic Security"
        id = "33d0a7b5-9280-450b-83a7-1737fad61e42"
        fingerprint = "79d6f041d933100c640aa7775a9862375baab351308f3492e182c47b24846bb1"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "67ebe950959d5c68b5d1423504d1aed80d38e0bfaf11943bb0a4b7303142e0ed"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 77 FE CF 9E 4D D9 53 10 06 4F CB 0E 42 81 0C 06 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_65514fe0 {
    meta:
        author = "Elastic Security"
        id = "65514fe0-9474-40eb-b899-1a2c608e5185"
        fingerprint = "9ba77d6e02e11f632faf36a35fbe45ca2b5deec62eaa11df43e1c83d78426c4f"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "0c5a1ab9360a9df7bc8d3fe9d8570e43aed3fd2d3ae91dab0ba045dd03e47e83"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 08 D4 BF 5A 52 9C 72 59 97 E0 F6 C5 26 49 5D 2F }
    condition:
        all of them
}

rule Windows_Generic_MalCert_7bfcc952 {
    meta:
        author = "Elastic Security"
        id = "7bfcc952-8243-4199-bbce-f904a397220d"
        fingerprint = "bdf093a252f2a7e0313bc42db4297d84017ea35003a8c3673c092565d9356ce1"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "4b264458f5383fdaab253b68eefaeee23de9702f12f1fbb0454d80b72692b5b5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 08 D2 A6 70 58 24 F5 5C 15 BF 66 C6 7D B5 23 A9 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a632cd10 {
    meta:
        author = "Elastic Security"
        id = "a632cd10-98f6-458c-9486-a8b4eb501480"
        fingerprint = "da193c254a17c5052c14ccabc7f6d334e3ac1c8db8be5402f6d9f5eb552b3a80"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "74b3248b91f953f2db5784807e5e5cd86b8a425ed9cc3c1abe9bee68fcb081b7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 11 44 D2 65 3D 4E 2A D1 9D B1 08 F8 66 19 49 81 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_1f95f236 {
    meta:
        author = "Elastic Security"
        id = "1f95f236-7069-4764-b3b1-e7e17f2e97b7"
        fingerprint = "77da46797fcd563e504f780c4b2622e780aa24d2dc4f243cdcad650e53fa748e"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "7e99bbab3a4b51999bfd80de8e8f5ecd4d1098757cb0f00202503fa7179c3a08"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 7F 89 B1 89 5D 7F 80 BD 14 C2 73 B8 7A 75 03 89 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_389a8f1e {
    meta:
        author = "Elastic Security"
        id = "389a8f1e-01e3-47ee-a82b-7ffb0bea951e"
        fingerprint = "92e8d1c4b84592d10f58bd0528bc01493927ae77ed94aebf722aa806b60db93a"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e87c99c87a42feba49f687bc7048ad3916297078d27a4aef3c037020158d216e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 0A B1 98 49 5D B9 8E 5E C6 1C D9 93 C6 A1 6F E7 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_2a954560 {
    meta:
        author = "Elastic Security"
        id = "2a954560-18c1-4f67-b614-92e153aa6c85"
        fingerprint = "17543b7278aa9ad89aef7ae206e0df2d913ced96bd577703be9a91bc3a47b818"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "fbd914b7d9019785d62c25ad164901752c5587c0847e32598e66fa25b6cf23cb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 77 E1 B3 58 54 DF A9 8B 97 02 C7 F4 C4 FE D6 0D }
    condition:
        all of them
}

rule Windows_Generic_MalCert_f32fdfcb {
    meta:
        author = "Elastic Security"
        id = "f32fdfcb-84f5-43c3-95a3-20bbe61c5dcc"
        fingerprint = "921e6fb10f1ef8719cb7b29f15b15b50cf65c5e21e55f5936089b9f53ea3e931"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "9c322e9a3500cf1cc38eecdd7952422f592551b9cd5493045d729d50de181a12"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 3C 0C DC E0 B2 56 10 11 DB 47 BC 01 1C 6D 7D EA }
    condition:
        all of them
}

rule Windows_Generic_MalCert_b8e60712 {
    meta:
        author = "Elastic Security"
        id = "b8e60712-1f7b-4314-a3aa-e841b13d7e92"
        fingerprint = "e9e3236ed9e352213bf24a6b55aa03a9b3f5414fb8ed77d4e19070bbce817c80"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "777325f2c769617cf01e9bfb305b5a47839a1c2c2d1ac067a018ba98781f80e0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 06 0F DF EF F7 3B 5C E4 69 E4 9A 78 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a925949c {
    meta:
        author = "Elastic Security"
        id = "a925949c-387d-403a-8a41-de5f0453764a"
        fingerprint = "a2a7c50ca9c703f0350e2b9cd1402634e22ca7dde9213227e3e7b5fb4144c8ea"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c33ea2ccb5a6e4aef16cfb18f64c5e459ce09d7d7d5dc963697c496e61f54a91"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 15 D2 21 01 46 49 44 AB 90 81 D4 0F }
    condition:
        all of them
}

rule Windows_Generic_MalCert_42e6a3ea {
    meta:
        author = "Elastic Security"
        id = "42e6a3ea-0d76-471c-8cd4-391124aa282d"
        fingerprint = "197ce5c581928092ed3a36b85b37172502ec5acf53beeb866aa50a2375875735"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "ebdd5efd08c7f68a57850f4967f259a1cd4acb035e5ca6bdfb64e22b17f3c671"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 07 53 C9 D0 B1 D9 AC 84 FD 84 DD BE E2 4D F8 92 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_4cfcf573 {
    meta:
        author = "Elastic Security"
        id = "4cfcf573-8a49-41cf-a091-2d73d7ecc2ac"
        fingerprint = "077d6c2bf401e36bb612a532e6ae290762f9cb593f8daa8af0fc5d247ba50e76"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "12c98ce7a4c92244ae122acc5d50745ee3d2de3e02d9b1b8a7e53a7b142f652f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 70 AA CF 51 0F 5C 8A 89 3C 51 04 B2 DB 31 56 33 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_5b803f85 {
    meta:
        author = "Elastic Security"
        id = "5b803f85-c9d1-4c97-b627-8221196c9f1a"
        fingerprint = "97e76657f7a70801613df3bf18b6bdad7d105cf6242e9a46bffa84dc13a896de"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "6bddbba9adc1a71c245705ca131c99f4d2739d684b71b2e6e197a724838af964"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 45 F7 5E 71 E7 32 09 CA 1E C5 D5 D5 D3 F2 88 81 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_9a68ab4c {
    meta:
        author = "Elastic Security"
        id = "9a68ab4c-d3ef-46bd-8c33-1f5d2c3352ca"
        fingerprint = "cfff03a13fabfa52c0be548ea670d4038cbca673e28e040d2a8a45f2915efc35"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "8cf87dc9c594d145782807f51404290806a2cbfd7b27a9287bf570393a0cb2da"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 D4 EF 46 9E 41 0A D1 3E 8E 08 DB E2 E9 AC 0F 93 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ac249f11 {
    meta:
        author = "Elastic Security"
        id = "ac249f11-12ed-434c-98c3-05d1c56c7a6a"
        fingerprint = "663a0260c32e4d1e5e1443e9f1b40e9ac0c5d8f1d2c8e2f7e4b42acb64b13fee"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "2449b3223695740b32c6c429ded948a49f20c569a8ebaae367936cc65a78a983"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 31 F7 D1 3B 36 05 F2 7A 3B 86 F2 BE }
    condition:
        all of them
}

rule Windows_Generic_MalCert_e659d934 {
    meta:
        author = "Elastic Security"
        id = "e659d934-f525-4051-b50f-8ac24f441854"
        fingerprint = "4116d6a514cd07e937fd2c2b0d53ae9ce78d553d8faf2ea2f8d4bcbc2034ad23"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "60ba61b8556e3535d9c66a5ea08bbd37fb07f7a03a35ce4663e9d8179186e1fc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 47 88 4E 54 A5 98 A9 0B FF 2B D3 18 38 01 02 67 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_1dac3f8f {
    meta:
        author = "Elastic Security"
        id = "1dac3f8f-bb36-411f-883e-57db1e6153cc"
        fingerprint = "0b29ddfe316ddc3d6792d4447a36f307e37c4bb8ee6cab5a7afb30d1cdacf74c"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5569d9ed0aaaf546f56f2ffc5b6e1ec8f7c2ec7be311477b64cc9062bb4b95a4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 C1 1E 1A A0 5B D7 47 EA B4 3F B3 1E B6 A5 31 DC }
    condition:
        all of them
}

rule Windows_Generic_MalCert_c31e42f7 {
    meta:
        author = "Elastic Security"
        id = "c31e42f7-a997-437f-8b64-26328bf97f0b"
        fingerprint = "c4408f5e02ea43d1b4ff93e5a34451757d342f21c69e5f66ba3cebafb6887083"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "17f3f4424afc18df18b9a9b36408e3f214ae91441f71e800f62dec240563dc6f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 84 9E A0 94 5D D2 EA 2D C3 CC 24 86 57 8A 57 15 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_152fa250 {
    meta:
        author = "Elastic Security"
        id = "152fa250-c1c7-4905-ac22-e4cdc6af9723"
        fingerprint = "356a6c2759878382eeef1c01b2027452bfa2ee3a495a1b8d10301a5f0a9da8e7"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5ded120267643bc09f3c66a9d64165c215d8f74b1b9b398b7864d1f61fbcfbdf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 14 C0 AF 4E AB D0 5E 63 C3 D4 B3 38 E0 BF B7 E3 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_728e5383 {
    meta:
        author = "Elastic Security"
        id = "728e5383-4c0e-47ee-ac69-9d6cf32a12cd"
        fingerprint = "b0401c8c080096af14ff86ac60d406b7359b06f67514e0fd7d0b4cb7b1022219"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "a4a1956522fefb1fd56af705b139320f39b0a5964d8d66c2c0bc6676dacd3983"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 DD 67 00 A6 3F D6 D3 A2 CF F5 F8 AC 95 54 FC 4A }
    condition:
        all of them
}

rule Windows_Generic_MalCert_45f72bf1 {
    meta:
        author = "Elastic Security"
        id = "45f72bf1-d065-4a84-bdb3-0598a704571a"
        fingerprint = "5362db78002b1ebd5ca65e3a22a43d8c789d31e6e60089643e3fa9feb5774b95"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "79b6e63218982c1e85a5e1798c5484e7e034cfecbe9f2da604f668fda8428af4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 69 C5 54 75 FF D7 B1 A2 47 42 96 E1 4C 5C F8 D9 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_2863b2d8 {
    meta:
        author = "Elastic Security"
        id = "2863b2d8-7759-44fa-81d3-4d196c426cd9"
        fingerprint = "aaffabc0edef460bb9c171bb9110468a26b6dbf176e4dfa957a2bf5915357f85"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "37223c02e25178395c05d47606b0d8c884a2b1151b59f701cc0d269d4408e1e5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 56 4C 3F 65 1F E5 1A 68 50 4F C9 7C }
    condition:
        all of them
}

rule Windows_Generic_MalCert_397a556e {
    meta:
        author = "Elastic Security"
        id = "397a556e-e296-462f-a6d6-1c2c14cee518"
        fingerprint = "c1f11e65e86c6e4d8e84ea9d3ac2f84102449c8c67cc445d4348e6a9885de203"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "f13869390dda83d40960d4f8a6b438c5c4cd31b4d25def7726c2809ddc573dc7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 1C E3 9E A1 C9 FC 35 F6 CC 05 A8 40 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_577c572d {
    meta:
        author = "Elastic Security"
        id = "577c572d-704a-4fda-9d4c-d2ce9400ac5d"
        fingerprint = "f6ccc743e6927fb0580a3c60a4ebc46a0f00335ac13325727759595b1659187b"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "a941413f86e84dfe14f1ef161ff0677971359fd5992f5463965e5754aca6115c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 4F AF 34 C6 62 37 73 26 A5 85 FD 91 02 8C 65 76 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a3c9c9be {
    meta:
        author = "Elastic Security"
        id = "a3c9c9be-51e3-42e2-b150-bbcb69343f15"
        fingerprint = "59595bf4e3cd8dc3468036485d525ebae590b7944d78cdb710a625b98b290cab"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "d860e6c483cae03f42fc3224db796a33289f48f85dcc8cd58bdc260f9e68f2ad"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 2F 14 7E DC 60 E9 34 24 AF 60 A7 AC }
    condition:
        all of them
}

rule Windows_Generic_MalCert_b650c953 {
    meta:
        author = "Elastic Security"
        id = "b650c953-0273-4e25-af00-110f76542372"
        fingerprint = "6d32dc006e2e32d13fa3ee7367ce1d187b5cbb4d7055c0e5119a93746dd5f06d"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "ceb75880148e05af7e9d029ee11d33535346ff5161b2bc506dbadd710688b9f3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 20 E6 5F 5D 29 B5 82 24 10 50 4B 1A C1 83 CA 3D }
    condition:
        all of them
}

rule Windows_Generic_MalCert_d15ca49f {
    meta:
        author = "Elastic Security"
        id = "d15ca49f-7571-45cd-b162-37872075a271"
        fingerprint = "1bbab9e46fbb7f4545c01557b62f428a38009421472e19498766884d65757f66"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e912bb10a2371ab0f884cd38bf2940e056f6d2e4aea4010303e98a7a5edcfcbf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 71 AC D1 EC EB 75 F9 2B DC CB DB 9E F3 6F DD EC }
    condition:
        all of them
}

rule Windows_Generic_MalCert_e507f27b {
    meta:
        author = "Elastic Security"
        id = "e507f27b-5c5a-4082-9270-7df5b47122ef"
        fingerprint = "6300d3bab1576ad5ab48ce1833cd5d6f10255510a1247fd5ab51f27d24c37b20"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "8b5af508dcee04dbb7dabdffeff03726ef821182ffdb8a930af57e9e71740440"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 7A 06 2E 41 04 BF 96 33 E5 CD AC 31 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ed5b8080 {
    meta:
        author = "Elastic Security"
        id = "ed5b8080-f173-47b5-b560-98c82a667754"
        fingerprint = "92f2506c459997e259f7970c931aafd5b52b074349b06286dafdc75e29a484c8"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "db827af8d120c894e82590ad6b4ca1d19e8f41541a7d3ea38734443d88deb6fd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 4B 6F 02 3B 59 59 7E 8E 95 3D B4 CD 7C 0B 52 5A }
    condition:
        all of them
}

rule Windows_Generic_MalCert_b8c63d0f {
    meta:
        author = "Elastic Security"
        id = "b8c63d0f-b546-4deb-8f23-c3d972bd8552"
        fingerprint = "b8a0cccc8663fc6dd9cd4db61349ee1a89c5709026ad6eb0070d64231483fca6"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "2f35445ba043097f38efbd160c6bdd6ba0f578165c295e6d31bfd179c3b6c4a1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 23 A5 73 F8 85 C7 1A 52 D7 A6 E3 21 75 96 CD F9 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_afe226f4 {
    meta:
        author = "Elastic Security"
        id = "afe226f4-ac89-4c2d-b607-4fe1f94efc72"
        fingerprint = "cc6655d96362d6d25064b2a959691c66bb66bca3a9c05fe6e19a8d52157ae251"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "3b66d49496a185b70e9f4a4681eca1e0f8a0d00fdff4f4f735b8c4232f65fb95"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 21 39 10 E0 20 B1 96 D0 A9 D3 53 B4 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_4b7c2e6d {
    meta:
        author = "Elastic Security"
        id = "4b7c2e6d-5533-4d77-8345-2aeedd029e59"
        fingerprint = "3217845523b768b4380ca64b7a6894491cf115bb973ed4669fc7d62473dd2a94"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "df0553b9d93edbbc386466b1992dce170ba8e8d5e1cad6b7598a3609d5f51b5f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 E4 0B 23 79 43 2D 73 AC B1 96 B9 D0 9A BC C5 87 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_d3a0db6b {
    meta:
        author = "Elastic Security"
        id = "d3a0db6b-61ce-4000-a3f5-bf6b7c7dd5dc"
        fingerprint = "3f89a2e00e85cd5f01564632c152ecdd22971b7a1a1381959571d475d592155d"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "d0ce783b1582863fa56696b8bc7c393723f9ff53552fadc221e516f39b3c165e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 08 32 EF 74 6F 16 E6 73 1B }
    condition:
        all of them
}

rule Windows_Generic_MalCert_148ea98b {
    meta:
        author = "Elastic Security"
        id = "148ea98b-a8ce-49b5-9808-289cdb7e0487"
        fingerprint = "9ddf8a9172c025d884f64f9e65159159d6e33daca7c13aeccf96372c7f5dccb0"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "eb8ddf6ffbb1ad3e234418b0f5fb0e6191a8c8a72f8ee460ae5f64ffa5484f3b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 D5 E3 54 50 B8 47 E0 61 38 C2 B4 74 49 25 D9 67 }
    condition:
        all of them
}

