rule Linux_Trojan_Generic_402be6c5 {
    meta:
        author = "Elastic Security"
        id = "402be6c5-a1d8-4d7a-88ba-b852e0db1098"
        fingerprint = "1e906f5a06f688084edf537ead0b7e887bd9e0fcc39990c976ea8c136dc52624"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "d30a8f5971763831f92d9a6dd4720f52a1638054672a74fdb59357ae1c9e6deb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 52 4C 95 42 11 01 64 E9 D7 39 E4 89 34 FA 48 01 02 C1 3B 39 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_5420d3e7 {
    meta:
        author = "Elastic Security"
        id = "5420d3e7-012f-4ce0-bb13-9e5221efa73e"
        fingerprint = "e81615b5756c2789b9be8fb10420461d5260914e16ba320cbab552d654bbbd8a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "103b8fced0aebd73cb8ba9eff1a55e6b6fa13bb0a099c9234521f298ee8d2f9f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 63 00 5F 5A 4E 34 41 52 43 34 37 65 6E 63 72 79 70 74 45 50 63 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_4f4cc3ea {
    meta:
        author = "Elastic Security"
        id = "4f4cc3ea-a906-4fce-a482-d762ab8995b8"
        fingerprint = "d85dac2bd81925f5d8c90c11047c631c1046767cb6649cd266c3a143353b6c12"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "32e25641360dbfd50125c43754cd327cf024f1b3bfd75b617cdf8a17024e2da5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4A 4E 49 20 55 4E 50 41 43 4B 20 44 45 58 20 53 54 41 52 54 20 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_703a0258 {
    meta:
        author = "Elastic Security"
        id = "703a0258-8d28-483e-a679-21d9ef1917b4"
        fingerprint = "796c2283eb14057081409800480b74ab684413f8f63a9db8704f5057026fb556"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "b086d0119042fc960fe540c23d0a274dd0fb6f3570607823895c9158d4f75974"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C2 F7 89 76 7E 86 87 F6 2B A3 2C 94 61 36 BE B6 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_378765e4 {
    meta:
        author = "Elastic Security"
        id = "378765e4-c0f2-42ad-a42b-b992d3b866f4"
        fingerprint = "60f259ba5ffe607b594c2744b9b30c35beab9683f4cd83c2e31556a387138923"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "1ed42910e09e88777ae9958439d14176cb77271edf110053e1a29372fce21ec1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 ?? FB FF FF 83 7D D4 00 79 0A B8 ?? 22 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_f657fb4f {
    meta:
        author = "Elastic Security"
        id = "f657fb4f-a065-4d51-bead-fd28f8053418"
        fingerprint = "8c15d5e53b95002f569d63c91db7858c4ca8f26c441cb348a1b34f3b26d02468"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "1ed42910e09e88777ae9958439d14176cb77271edf110053e1a29372fce21ec1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 ?? FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_be1757ef {
    meta:
        author = "Elastic Security"
        id = "be1757ef-cf45-4c00-8d6c-dbb0f44f6efb"
        fingerprint = "0af6b01197b63259d9ecbc24f95b183abe7c60e3bf37ca6ac1b9bc25696aae77"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "f3e4e2b5af9d0c72aae83cec57e5c091a95c549f826e8f13559aaf7d300f6e13"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 54 68 75 20 4D 61 72 20 31 20 31 34 3A 34 34 3A 30 38 20 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_7a95ef79 {
    meta:
        author = "Elastic Security"
        id = "7a95ef79-3df5-4f7a-a8ba-00577473b288"
        fingerprint = "aadec0fa964f94afb725a568dacf21e80b80d359cc5dfdd8d028aaece04c7012"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "f59340a740af8f7f4b96e3ea46d38dbe81f2b776820b6f53b7028119c5db4355"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 1C 8B 54 24 20 8B 74 24 24 CD 80 5E 5A 59 5B C3 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_1c5e42b7 {
    meta:
        author = "Elastic Security"
        id = "1c5e42b7-b873-443e-a30c-66a75fc39b21"
        fingerprint = "b64284e1220ec9abc9b233e513020f8b486c76f91e4c3f2a0a6fb003330c2535"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "b078a02963610475217682e6e1d6ae0b30935273ed98743e47cc2553fbfd068f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C0 89 45 F4 83 7D F4 FF 75 1C 83 EC 0C 68 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_8ca4b663 {
    meta:
        author = "Elastic Security"
        id = "8ca4b663-b282-4322-833a-4c0143f63634"
        fingerprint = "34e04e32ee493643cc37ff0cfb94dcbc91202f651bc2560e9c259b53a9d6acfc"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "1ddf479e504867dfa27a2f23809e6255089fa0e2e7dcf31b6ce7d08f8d88947e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 28 60 DF F2 FB B7 E7 EB 96 D1 E6 96 88 12 96 EB 8C 94 EB C7 4E }
    condition:
        all of them
}

rule Linux_Trojan_Generic_d3fe3fae {
    meta:
        author = "Elastic Security"
        id = "d3fe3fae-f7ec-48d5-8b17-9ab11a5b689f"
        fingerprint = "1773a3e22cb44fe0b3e68d343a92939a955027e735c60b48cf3b7312ce3a6415"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "2a2542142adb05bff753e0652e119c1d49232d61c49134f13192425653332dc3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 47 53 45 54 2C 20 70 69 64 2C 20 4E 54 5F 50 52 53 54 41 54 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_5e981634 {
    meta:
        author = "Elastic Security"
        id = "5e981634-e34e-4943-bf8f-86cfd9fffc85"
        fingerprint = "57f1e8fa41f6577f41a73e3460ef0c6c5b0a65567ae0962b080dfc8ab18364f5"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "448e8d71e335cabf5c4e9e8d2d31e6b52f620dbf408d8cc9a6232a81c051441b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 1D 8B 44 24 68 89 84 24 A4 00 00 00 8B 44 24 6C 89 84 24 A8 00 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_d8953ca0 {
    meta:
        author = "Elastic Security"
        id = "d8953ca0-f1f1-4d76-8c80-06f16998ba03"
        fingerprint = "16ab55f99be8ed2a47618978a335a8c68369563c0a4d0a7ff716b5d4c9e0785c"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "552753661c3cc7b3a4326721789808482a4591cb662bc813ee50d95f101a3501"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5B 9C 9C 9C 9C 5C 5D 5E 5F 9C 9C 9C 9C B1 B2 B3 B4 9C 9C 9C 9C }
    condition:
        all of them
}

rule Linux_Trojan_Generic_181054af {
    meta:
        author = "Elastic Security"
        id = "181054af-dc05-4981-8a57-ea17ffd6241f"
        fingerprint = "8ef033ac0fccd10cdf2e66446461b7c8b29574e5869440a1972dbe4bb5fbed89"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "e677f1eed0dbb4c680549e0bf86d92b0a28a85c6d571417baaba0d0719da5f93"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6D 6F 64 00 73 65 74 75 74 78 65 6E 74 00 67 6D 74 69 6D 65 00 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_c3d529a2 {
    meta:
        author = "Elastic Security"
        id = "c3d529a2-f2c7-41de-ba2a-2cbf2eb4222c"
        fingerprint = "72ef5b28489e01c3f2413b9a907cda544fc3f60e00451382e239b55ec982f187"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "b46135ae52db6399b680e5c53f891d101228de5cd6c06b6ae115e4a763a5fb22"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 1C 31 C0 5B 5E 5F 5D C3 8B 1C 24 C3 8D 64 24 04 53 8B DA 5B }
    condition:
        all of them
}

rule Linux_Trojan_Generic_4675dffa {
    meta:
        author = "Elastic Security"
        id = "4675dffa-0536-4a4d-bedb-f8c7fa076168"
        fingerprint = "7aa556e481694679ce0065bcaaa4d35e2c2382326681f03202b68b1634db08ab"
        creation_date = "2023-07-28"
        last_modified = "2024-02-13"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "43e14c9713b1ca1f3a7f4bcb57dd3959d3a964be5121eb5aba312de41e2fb7a6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = ", i = , not , val ./zzzz.local.onion"
        $a2 = { 61 74 20 20 25 76 3D 25 76 2C 20 28 63 6F 6E 6E 29 20 28 73 63 61 6E 20 20 28 73 63 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_5e3bc3b3 {
    meta:
        author = "Elastic Security"
        id = "5e3bc3b3-c708-49dd-80c6-0d353acb4b53"
        fingerprint = "cf1c66af92607d0ec76ec1db0292fcb8035bdc85117dc714bdade32740d5a835"
        creation_date = "2024-09-20"
        description = "Rule for custom Trojan found in Linux REF6138."
        last_modified = "2024-11-04"
        threat_name = "Linux.Trojan.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $enc1 = { 74 73 0A 1C 1A 54 1A 11 54 0C 18 43 59 5B 3A 11 0B 16 14 10 0C 14 5B }
        $enc2 = { 18 1A 1A 1C 09 0D 43 59 0D 1C 01 0D 56 11 0D 14 15 55 18 09 09 15 10 }
        $enc3 = { 18 1A 1A 1C 09 0D 54 15 18 17 1E 0C 18 1E 1C 43 59 0B 0C }
        $enc4 = { 34 16 03 10 15 15 18 56 4C 57 49 59 51 2E 10 17 1D 16 0E 0A 59 37 }
        $key = "yyyyyyyy"
    condition:
        1 of ($enc*) and $key
}

