rule Linux_Hacktool_Flooder_825b6808 {
    meta:
        author = "Elastic Security"
        id = "825b6808-9b23-4a55-9f26-a34cab6ea92b"
        fingerprint = "e2db86e614b9bc0de06daf626abe652cc6385cca8ba96a2f2e394cf82be7a29b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "7db9a0760dd16e23cb299559a0e31a431b836a105d5309a9880fa4b821937659"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 83 EC 04 8B 45 E4 FF 70 0C 8D 45 E8 83 C0 04 50 8B 45 E4 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_a44ab8cd {
    meta:
        author = "Elastic Security"
        id = "a44ab8cd-c45e-4fe8-b96d-d4fe227f3107"
        fingerprint = "0d77547064aeca6714ede98df686011c139ca720a71bcac23e40b0c02d302d6a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "4b2068a4a666b0279358b8eb4f480d2df4c518a8b4518d0d77c6687c3bff0a32"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E0 03 48 89 45 A8 8B 45 BC 48 63 D0 48 83 EA 01 48 89 55 A0 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_7026f674 {
    meta:
        author = "Elastic Security"
        id = "7026f674-83b7-432b-9197-2d71abdb9579"
        fingerprint = "acf93628ecbda544c6c5d88388ac85bb2755c71544a0980ee1b2854c6bdb7c77"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "b7a77ebb66664c54d01a57abed5bb034ef2933a9590b595bba0566938b099438"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 08 1E 77 DA 00 43 6F 75 6C 64 20 6E 6F 74 20 6F 70 65 6E 20 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_761ad88e {
    meta:
        author = "Elastic Security"
        id = "761ad88e-1667-4253-81f6-52c92e0ccd68"
        fingerprint = "14e701abdef422dcde869a2278ec6e1fb7889dcd9681a224b29a00bcb365e391"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1d88971f342e4bc4e6615e42080a3b6cec9f84912aa273c36fc46aaf86ff6771"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2E 31 36 38 2E 33 2E 31 30 30 00 43 6F 75 6C 64 20 6E 6F 74 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_b93655d3 {
    meta:
        author = "Elastic Security"
        id = "b93655d3-1d3f-42f4-a47f-a69624e90da5"
        fingerprint = "55119467cb5f9789b74064e63c1e7d905457b54f6e4da1a83c498313d6c90b5b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 49 89 C5 74 45 45 85 F6 7E 28 48 89 C3 41 8D 46 FF 4D 8D 64 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_af9f75e6 {
    meta:
        author = "Elastic Security"
        id = "af9f75e6-9a9b-4e03-9c76-8c0c9f07c8b1"
        fingerprint = "f6e7d6e9c03c8ce3e14b214fe268e7aab2e15c1b4378fe253021497fb9a884e6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "bf6f3ffaf94444a09b69cbd4c8c0224d7eb98eb41514bdc3f58c1fb90ac0e705"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C4 48 89 E0 48 83 C0 07 48 C1 E8 03 48 C1 E0 03 48 89 45 C0 C7 45 B4 14 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_1bf0e994 {
    meta:
        author = "Elastic Security"
        id = "1bf0e994-2648-4dbb-9b9c-b86b9a347700"
        fingerprint = "1f844c349b47dd49a75d50e43b6664e9d2b95c362efb730448934788b6bddb79"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1ea2dc13eec0d7a8ec20307f5afac8e9344d827a6037bb96a54ad7b12f65b59c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 05 88 10 48 8B 45 B8 0F B6 10 83 E2 0F 83 CA 40 88 10 48 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_d710a5da {
    meta:
        author = "Elastic Security"
        id = "d710a5da-26bf-4f6a-bf51-9cdac1f83aa3"
        fingerprint = "e673aa8785c7076f4cced9f12b284a2927b762fe1066aba8d6a5ace775f3480c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "ba895a9c449bf9bf6c092df88b6d862a3e8ed4079ef795e5520cb163a45bcdb4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 24 48 8B 45 E0 48 83 C0 10 48 8B 08 48 8B 45 E0 48 83 C0 08 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_f434a3fb {
    meta:
        author = "Elastic Security"
        id = "f434a3fb-e5fd-4749-8e53-fc6c80ee5406"
        fingerprint = "b74e55c56a063e14608f7e8f578cc3c74ec57954df39e63e49b60c0055725d51"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "ba895a9c449bf9bf6c092df88b6d862a3e8ed4079ef795e5520cb163a45bcdb4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 48 01 45 F8 48 83 45 E8 02 83 6D E4 01 83 7D E4 00 7F E3 48 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_a2795a4c {
    meta:
        author = "Elastic Security"
        id = "a2795a4c-16c0-4237-a014-3570d1edb287"
        fingerprint = "7c8bf248b159f3a140f10cd40d182fa84f334555b92306e6f44e746711b184cc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "9a564d6b29d2aaff960e6f84cd0ef4c701fefa2a62e2ea690106f3fdbabb0d71"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 8B 45 D8 66 89 50 04 48 8B 45 D8 0F B7 40 02 66 D1 E8 0F }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_678c1145 {
    meta:
        author = "Elastic Security"
        id = "678c1145-cc41-4e83-bc88-30f64da46dd3"
        fingerprint = "f4f66668b45f520bc107b7f671f8c7f42073d7ff28863e846a74fbd6cac03e87"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "559793b9cb5340478f76aaf5f81c8dbfbcfa826657713d5257dac3c496b243a6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C8 48 BA AB AA AA AA AA AA AA AA 48 89 C8 48 F7 E2 48 C1 EA 05 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_3cbdfb1f {
    meta:
        author = "Elastic Security"
        id = "3cbdfb1f-6c66-48be-931e-3ae609c46ff4"
        fingerprint = "c7f5d7641ea6e780bc3045181c929be73621acfe6aec4d157f6a9e0334ba7fb9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "bd40ac964f3ad2011841c7eb4bf7cab332d4d95191122e830ab031dc9511c079"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5B 53 54 44 32 2E 43 20 42 59 20 53 54 41 43 4B 44 5D 20 53 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_8b63ff02 {
    meta:
        author = "Elastic Security"
        id = "8b63ff02-be86-4c63-8f7b-4c70fbd8a83a"
        fingerprint = "af7a4df7e707c1b70fb2b29efe2492e6f77cdde5e8d1e6bfdf141acabc8759eb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "a57de6cd3468f55b4bfded5f1eed610fdb2cbffbb584660ae000c20663d5b304"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { DC 02 83 7D DC 01 0F 9F C0 84 C0 75 DF 83 7D DC 01 75 1D 66 C7 45 F6 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_30973084 {
    meta:
        author = "Elastic Security"
        id = "30973084-60d2-494d-a3c6-2a015a9459a0"
        fingerprint = "44fc236199ccf53107f1a617ac872f51d58a99ec242fe97b913e55b3ec9638e2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "a22ffa748bcaaed801f48f38b26a9cfdd5e62183a9f6f31c8a1d4a8443bf62a4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4C 69 73 74 20 49 6D 70 6F 72 74 20 46 6F 72 20 53 6F 75 72 63 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_1cfa95dd {
    meta:
        author = "Elastic Security"
        id = "1cfa95dd-e768-4071-9038-389c580741f9"
        fingerprint = "6ec21acb987464613830b3bbe1e2396093d269dae138c68fe77f35d88796001e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1d88971f342e4bc4e6615e42080a3b6cec9f84912aa273c36fc46aaf86ff6771"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 7D EC 00 7E 0F 48 8B 45 F0 0F B6 00 0F B6 C0 48 01 C3 EB 10 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_25c48456 {
    meta:
        author = "Elastic Security"
        id = "25c48456-2f83-41a8-ba37-b557014d1d86"
        fingerprint = "0c79f8eaacd2aa1fa60d5bfb7b567a9fc3e65068be1516ca723cb1394bb564ce"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "eba6f3e4f7b53e22522d82bdbdf5271c3fc701cbe07e9ecb7b4c0b85adc9d6b4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 F8 48 83 6D E0 01 48 83 7D E0 00 75 DD 48 8B 45 F0 C9 C3 55 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_b1ca2abd {
    meta:
        author = "Elastic Security"
        id = "b1ca2abd-b8ab-435d-85b6-a1c93212e492"
        fingerprint = "214c9dedf34b2c8502c6ef14aff5727ac5a2941e1a8278a48d34fea14d584a1a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1d88971f342e4bc4e6615e42080a3b6cec9f84912aa273c36fc46aaf86ff6771"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C4 48 89 E0 48 83 C0 07 48 C1 E8 03 48 C1 E0 03 48 89 45 B0 C7 45 AC 14 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_cce8c792 {
    meta:
        author = "Elastic Security"
        id = "cce8c792-ef3e-43c2-b4ad-343de6a69cc7"
        fingerprint = "03541eb8a293e88c0b8e6509310f8c57f2cd16b5ff76783a73bde2b614b607fc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "ea56da9584fc36dc67cb1e746bd13c95c4d878f9d594e33221baad7e01571ee6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 48 89 51 08 48 8B 45 A0 8B 55 CC 48 63 D2 48 C1 E2 05 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_4bcea1c4 {
    meta:
        author = "Elastic Security"
        id = "4bcea1c4-de08-4526-8d31-89c5512f07af"
        fingerprint = "e859966e8281e024c82dedd5bd237ab53af28a0cb21d24daa456e5cd1186c352"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "9a564d6b29d2aaff960e6f84cd0ef4c701fefa2a62e2ea690106f3fdbabb0d71"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 50 FF 48 8B 45 C0 48 01 D0 0F B6 00 3C 0A 74 22 48 8B 45 C0 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_ab561a1b {
    meta:
        author = "Elastic Security"
        id = "ab561a1b-d8dd-4768-9b4c-07ef4777b252"
        fingerprint = "081dd5eb061c8023756e413420241e20a2c86097f95859181ca5d6b1d24fdd76"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1b7df0d491974bead05d04ede6cf763ecac30ecff4d27bb4097c90cc9c3f4155"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B5 50 FF FF FF 64 48 8B 04 25 28 00 00 00 48 89 45 C8 31 C0 83 BD 5C FF FF }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_1a4eb229 {
    meta:
        author = "Elastic Security"
        id = "1a4eb229-a194-46a5-8e93-370a40ba999b"
        fingerprint = "de076ef23c2669512efc00ddfe926ef04f8ad939061c69131a0ef9a743639371"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "bf6f3ffaf94444a09b69cbd4c8c0224d7eb98eb41514bdc3f58c1fb90ac0e705"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F4 8B 45 E8 83 C0 01 89 45 F8 EB 0F 8B 45 E8 83 C0 01 89 45 F4 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_51ef0659 {
    meta:
        author = "Elastic Security"
        id = "51ef0659-2691-4558-bff8-fce614f10ab9"
        fingerprint = "41f517a19a3c4dc412200b683f4902a656f3dcfdead8b8292e309413577c3850"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "b7a2bc75dd9c44c38b2a6e4e7e579142ece92a75b8a3f815940c5aa31470be2b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E0 03 48 89 45 B0 8B 45 9C 48 63 D0 48 83 EA 01 48 89 55 B8 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_d90c4cbe {
    meta:
        author = "Elastic Security"
        id = "d90c4cbe-4d0a-4341-a58b-a472b67282d6"
        fingerprint = "64796aa7faa2e945b5c856c1c913cb62175413dc1df88505dececcfbd2878cb1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 D8 F7 D0 5B 5D C3 55 48 89 E5 48 83 EC 40 48 89 7D C8 48 89 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_c680c9fd {
    meta:
        author = "Elastic Security"
        id = "c680c9fd-34ad-4d92-b8d6-1b511c7c07a3"
        fingerprint = "5cb5b36d3ae5525b992a9d395b54429f52b11ea229e0cecbd62317af7b5faf84"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "ea56da9584fc36dc67cb1e746bd13c95c4d878f9d594e33221baad7e01571ee6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 A0 8B 55 CC 48 63 D2 48 C1 E2 05 48 01 D0 48 8D 48 10 48 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_e63396f4 {
    meta:
        author = "Elastic Security"
        id = "e63396f4-a297-4d99-b341-34cb22498078"
        fingerprint = "269285d03ea1a3b41ff134ab2cf5e22502626c72401b83add6c1e165f4dd83f8"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "913e6d2538bd7eed3a8f3d958cf445fe11c5c299a70e5385e0df6a9b2f638323"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 02 83 45 FC 01 81 7D FC FF 0F 00 00 7E ?? 90 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_7d5355da {
    meta:
        author = "Elastic Security"
        id = "7d5355da-5fbd-46c0-8bd2-33a27cbcca63"
        fingerprint = "52882595f28e1778ee3b0e6bda94319f5c348523f16566833281f19912360270"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference = "03397525f90c8c2242058d2f6afc81ceab199c5abcab8fd460fabb6b083d8d20"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 83 EC 60 64 48 8B 04 25 28 00 00 00 48 89 45 F8 31 C0 BF 0A 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_a9e8a90f {
    meta:
        author = "Elastic Security"
        id = "a9e8a90f-5d95-4f4e-a9e0-c595be3729dd"
        fingerprint = "a06bbcbc09e5e44447b458d302c47e4f18438be8d57687700cb4bf3f3630fba8"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference = "0558cf8cab0ba1515b3b69ac32975e5e18d754874e7a54d19098e7240ebf44e4"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 D8 48 89 45 F0 66 C7 45 EE 00 00 EB 19 48 8B 45 F0 48 8D }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_a598192a {
    meta:
        author = "Elastic Security"
        id = "a598192a-c804-4c57-9cc3-c2205cb431d3"
        fingerprint = "61cb72180283746ebbd82047baffc4bf2384658019970c4dceadfb5c946abcd2"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference = "101f2240cd032831b9c0930a68ea6f74688f68ae801c776c71b488e17bc71871"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8D 65 D8 5B 5E 5F C9 C3 8D 36 55 89 E5 83 EC 18 57 56 53 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_53bf4e37 {
    meta:
        author = "Elastic Security"
        id = "53bf4e37-e043-4cf2-ad2a-bc63d69585ae"
        fingerprint = "83e804640b0848caa532dadc33923c226a34e0272457bde00325069ded55f256"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference = "101f2240cd032831b9c0930a68ea6f74688f68ae801c776c71b488e17bc71871"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 00 49 50 5F 48 44 52 49 4E 43 4C 00 57 68 61 74 20 74 68 65 20 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_50158a6e {
    meta:
        author = "Elastic Security"
        id = "50158a6e-d412-4e37-a8b5-c7c79a2a5393"
        fingerprint = "f6286d1fd84aad72cdb8c655814a9df1848fae94ae931ccf62187c100b27a349"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference = "1e0cdb655e48d21a6b02d2e1e62052ffaaec9fdfe65a3d180fc8afabc249e1d8"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 F8 48 01 D0 48 89 45 D8 0F B7 45 E6 48 8D 50 33 48 8B 45 F8 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_f454ec10 {
    meta:
        author = "Elastic Security"
        id = "f454ec10-7a67-4717-9e95-fecb7c357566"
        fingerprint = "2ae5e2c3190a4ce5d238efdb10ac0520987425fb7af52246b6bf948abd0259da"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Hacktool.Flooder"
        reference = "0297e1ad6e180af85256a175183102776212d324a2ce0c4f32e8a44a2e2e9dad"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 EC 48 63 D0 48 8B 45 D0 48 01 D0 0F B6 00 3C 2E 75 4D 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_9417f77b {
    meta:
        author = "Elastic Security"
        id = "9417f77b-190b-4834-b57a-08a7cbfac884"
        fingerprint = "d321ea7aeb293f8f50236bddeee99802225b70e8695bb3527a89beea51e3ffb3"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Hacktool.Flooder"
        reference = "60ff13e27dad5e6eadb04011aa653a15e1a07200b6630fdd0d0d72a9ba797d68"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F B7 45 F6 0F B7 C0 48 01 C3 48 89 DA 48 C1 FA 10 0F B7 C3 48 8D }
    condition:
        all of them
}

