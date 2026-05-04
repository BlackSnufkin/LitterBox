rule Linux_Trojan_Gafgyt_83715433 {
    meta:
        author = "Elastic Security"
        id = "83715433-3dff-4238-8cdb-c51279565e05"
        fingerprint = "25ac15f4b903d9e28653dad0db399ebd20d4e9baabf5078fbc33d3cd838dd7e9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "3648a407224634d76e82eceec84250a7506720a7f43a6ccf5873f478408fedba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 08 88 10 FF 45 08 8B 45 08 0F B6 00 84 C0 75 DB C9 C3 55 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_28a2fe0c {
    meta:
        author = "Elastic Security"
        id = "28a2fe0c-eed5-4c79-81e6-3b11b73a4ebd"
        fingerprint = "a2c6beaec18ca876e8487c11bcc7a29279669588aacb7d3027d8d8df8f5bcead"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2F 78 33 38 2F 78 46 4A 2F 78 39 33 2F 78 49 44 2F 78 39 41 2F 78 33 38 2F 78 46 4A 2F }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_eb96cc26 {
    meta:
        author = "Elastic Security"
        id = "eb96cc26-e6d6-4388-a5da-2501e6e2ea32"
        fingerprint = "73967a3499d5dce61735aa2d352c1db48bb1d965b2934bb924209d729b5eb162"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "440318179ba2419cfa34ea199b49ee6bdecd076883d26329bbca6dca9d39c500"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 49 6E 66 6F 3A 20 0A 00 5E 6A 02 5F 6A 01 58 0F 05 6A 7F 5F }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_5008aee6 {
    meta:
        author = "Elastic Security"
        id = "5008aee6-3866-4f0a-89bf-bde740baee5c"
        fingerprint = "6876a6c1333993c4349e459d4d13c11be1b0f78311274c0f778e65d0fabeeaa7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "b32cd71fcfda0a2fcddad49d8c5ba8d4d68867b2ff2cb3b49d1a0e358346620c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 50 16 B4 87 58 83 00 21 84 51 FD 13 4E 79 28 57 C3 8B 30 55 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6321b565 {
    meta:
        author = "Elastic Security"
        id = "6321b565-ed25-4bf2-be4f-3ffa0e643085"
        fingerprint = "c1d286e82426cbf19fc52836ef9a6b88c1f6e144967f43760df93cf1ab497d07"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "cd48addd392e7912ab15a5464c710055f696990fab564f29f13121e7a5e93730"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D8 89 D0 01 C0 01 D0 C1 E0 03 8B 04 08 83 E0 1F 0F AB 84 9D 58 FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a6a2adb9 {
    meta:
        author = "Elastic Security"
        id = "a6a2adb9-9d54-42d4-abed-5b30d8062e97"
        fingerprint = "cdd0bb9ce40a000bb86b0c76616fe71fb7dbb87a044ddd778b7a07fdf804b877"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CC 01 C2 89 55 B4 8B 45 B4 C9 C3 55 48 89 E5 48 81 EC 90 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_c573932b {
    meta:
        author = "Elastic Security"
        id = "c573932b-9b3f-4ab7-a6b6-32dcc7473790"
        fingerprint = "18a3025ebb8af46605970ee8d7d18214854b86200001d576553e102cb71df266"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 7D 18 00 74 22 8B 45 1C 83 E0 02 85 C0 74 18 83 EC 08 6A 2D FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a10161ce {
    meta:
        author = "Elastic Security"
        id = "a10161ce-62e0-4f60-9de7-bd8caf8618be"
        fingerprint = "77e89011a67a539954358118d41ad3dabde0e69bac2bbb2b2da18eaad427d935"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 B0 8B 45 BC 48 63 D0 48 89 D0 48 C1 E0 02 48 8D 14 10 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_ae01d978 {
    meta:
        author = "Elastic Security"
        id = "ae01d978-d07d-4813-a22b-5d172c477d08"
        fingerprint = "2d937c6009cfd53e11af52482a7418546ae87b047deabcebf3759e257cd89ce1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 2C 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9e9530a7 {
    meta:
        author = "Elastic Security"
        id = "9e9530a7-ad4d-4a44-b764-437b7621052f"
        fingerprint = "d6ad6512051e87c8c35dc168d82edd071b122d026dce21d39b9782b3d6a01e50"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F6 48 63 FF B8 36 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_5bf62ce4 {
    meta:
        author = "Elastic Security"
        id = "5bf62ce4-619b-4d46-b221-c5bf552474bb"
        fingerprint = "3ffc398303f7208e77c4fbdfb50ac896e531b7cee3be2fa820bc8d70cfb20af3"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 56 53 31 F6 8D 45 10 83 EC 10 89 45 F4 8B 55 F4 46 8D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_f3d83a74 {
    meta:
        author = "Elastic Security"
        id = "f3d83a74-2888-435a-9a3c-b7de25084e9a"
        fingerprint = "1c5df68501b688905484ed47dc588306828aa7c114644428e22e5021bb39bd4a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { DC 00 74 1B 83 7D E0 0A 75 15 83 7D E4 00 79 0F C7 45 C8 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_807911a2 {
    meta:
        author = "Elastic Security"
        id = "807911a2-f6ec-4e65-924f-61cb065dafc6"
        fingerprint = "f409037091b7372f5a42bbe437316bd11c655e7a5fe1fcf83d1981cb5c4a389f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FE 48 39 F3 0F 94 C2 48 83 F9 FF 0F 94 C0 84 D0 74 16 4B 8D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9c18716c {
    meta:
        author = "Elastic Security"
        id = "9c18716c-e5cd-4b4f-98e2-0daed77f34cd"
        fingerprint = "351772d2936ec1a14ee7e2f2b79a8fde62d02097ae6a5304c67e00ad1b11085a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FC 80 F6 FE 59 21 EC 75 10 26 CF DC 7B 5A 5B 4D 24 C9 C0 F3 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_fbed4652 {
    meta:
        author = "Elastic Security"
        id = "fbed4652-2c68-45c6-8116-e3fe7d0a28b8"
        fingerprint = "a08bcc7d0999562b4ef2d8e0bdcfa111fe0f76fc0d3b14d42c8e93b7b90abdca"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "2ea21358205612f5dc0d5f417c498b236c070509531621650b8c215c98c49467"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 02 00 00 2B 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_e0673a90 {
    meta:
        author = "Elastic Security"
        id = "e0673a90-165e-4347-a965-e8d14fdf684b"
        fingerprint = "6834f65d54bbfb926f986fe2dd72cd30bf9804ed65fcc71c2c848e72350f386a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 E8 0F B6 00 84 C0 74 17 48 8B 75 E8 48 FF C6 48 8B 7D F0 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_821173df {
    meta:
        author = "Elastic Security"
        id = "821173df-6835-41e1-a662-a432abf23431"
        fingerprint = "c311789e1370227f7be1d87da0c370a905b7f5b4c55cdee0f0474060cc0fc5e4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "de7d1aff222c7d474e1a42b2368885ef16317e8da1ca3a63009bf06376026163"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D0 48 FF C8 48 03 45 F8 48 FF C8 C6 00 00 48 8B 45 F8 48 C7 C1 FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_31796a40 {
    meta:
        author = "Elastic Security"
        id = "31796a40-1cbe-4d0c-a785-d16f40765f4a"
        fingerprint = "0a6c56eeed58a1a100c9b981157bb864904ffddb3a0c4cb61ec4cc0d770d68ae"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "227c7f13f7bdadf6a14cc85e8d2106b9d69ab80abe6fc0056af5edef3621d4fb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 14 48 63 D0 48 8D 45 C0 48 8D 70 04 48 8B 45 E8 48 8B 40 18 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_750fe002 {
    meta:
        author = "Elastic Security"
        id = "750fe002-cac1-4832-94d2-212aa5ec17e3"
        fingerprint = "f51347158a6477b0da4ed4df3374fbad92b6ac137aa4775f83035d1e30cba7dc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 8B 45 0C 40 8A 00 3C FC 75 06 C6 45 FF FE EB 50 8B 45 0C 40 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6122acdf {
    meta:
        author = "Elastic Security"
        id = "6122acdf-1eef-45ea-83ea-699d21c2dc20"
        fingerprint = "283275705c729be23d7dc75056388ecae00390bd25ee7b66b0cfc9b85feee212"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 B0 00 FC 8B 7D E8 F2 AE 89 C8 F7 D0 48 48 89 45 F8 EB 03 FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a0a4de11 {
    meta:
        author = "Elastic Security"
        id = "a0a4de11-fe65-449f-a990-ad5f18ac66f0"
        fingerprint = "891cfc6a4c38fb257ada29050e0047bd1301e8f0a6a1a919685b1fcc2960b047"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "cf1ca1d824c8687e87a5b0275a0e39fa101442b4bbf470859ddda9982f9b3417"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 42 0D 83 C8 10 88 42 0D 48 8B 55 D8 0F B6 42 0D 83 C8 08 88 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a473dcb6 {
    meta:
        author = "Elastic Security"
        id = "a473dcb6-887e-4a9a-a1f2-df094f1575b9"
        fingerprint = "6119a43aa5c9f61249083290293f15696b54b012cdf92553fd49736d40c433f9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "7ba74e3cb0d633de0e8dbe6cfc49d4fc77dd0c02a5f1867cc4a1f1d575def97d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 49 56 04 0B 1E 46 1E B0 EB 10 18 38 38 D7 80 4D 2D 03 29 62 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_30444846 {
    meta:
        author = "Elastic Security"
        id = "30444846-439f-41e1-b0b4-c12da774a228"
        fingerprint = "3c74db508de7c8c1c190d5569e0a2c2b806f72045e7b74d44bfbaed20ecb956b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "c84b81d79d437bb9b8a6bad3646aef646f2a8e1f1554501139648d2f9de561da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 64 20 2B 78 20 74 66 74 70 31 2E 73 68 3B 20 73 68 20 74 66 74 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_ea92cca8 {
    meta:
        author = "Elastic Security"
        id = "ea92cca8-bba7-4a1c-9b88-a2d051ad0021"
        fingerprint = "aa4aee9f3d6bedd8234eaf8778895a0f5d71c42b21f2a428f01f121e85704e8e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 53 65 6C 66 20 52 65 70 20 46 75 63 6B 69 6E 67 20 4E 65 54 69 53 20 61 6E 64 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d4227dbf {
    meta:
        author = "Elastic Security"
        id = "d4227dbf-6ab4-4637-a6ba-0e604acaafb4"
        fingerprint = "58c4b1d4d167876b64cfa10f609911a80284180e4db093917fea16fae8ccd4e3"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF 48 81 EC D0 00 00 00 48 8D 84 24 E0 00 00 00 48 89 54 24 30 C7 04 24 18 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_09c3070e {
    meta:
        author = "Elastic Security"
        id = "09c3070e-4b71-45a0-aa62-0cc6e496644a"
        fingerprint = "84fad96b60b297736c149e14de12671ff778bff427ab7684df2c541a6f6d7e7d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 C1 E8 06 48 89 C6 48 8B 94 C5 50 FF FF FF 8B 8D 2C FF FF FF 83 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_fa19b8fc {
    meta:
        author = "Elastic Security"
        id = "fa19b8fc-6035-4415-842f-4993411ab43e"
        fingerprint = "4f213d5d1b4a0b832ed7a6fac91bef7c29117259b775b85409e9e4c8aec2ad10"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "a7cfc16ec33ec633cbdcbff3c4cefeed84d7cbe9ca1f4e2a3b3e43d39291cd6b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 02 63 10 01 0F 4B 85 14 36 B0 60 53 03 4F 0D B2 05 76 02 B7 00 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_eaa9a668 {
    meta:
        author = "Elastic Security"
        id = "eaa9a668-e3b9-4657-81bf-1c6456e2053a"
        fingerprint = "bee2744457164e5747575a101026c7862474154d82f52151ac0d77fb278d9405"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 C0 0F B6 00 3C 2F 76 0B 48 8B 45 C0 0F B6 00 3C 39 76 C7 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_46eec778 {
    meta:
        author = "Elastic Security"
        id = "46eec778-7342-4ef7-adac-35bc0cdb9867"
        fingerprint = "2602371a40171870b1cf024f262e95a2853de53de39c3a6cd3de811e81dd3518"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "9526277255a8d632355bfe54d53154c9c54a4ab75e3ba24333c73ad0ed7cadb1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 01 45 F8 48 83 45 E8 02 83 6D C8 02 83 7D C8 01 7F E4 83 7D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_f51c5ac3 {
    meta:
        author = "Elastic Security"
        id = "f51c5ac3-ade9-4d01-b578-3473a2b116db"
        fingerprint = "34f254afdf94b1eb29bae4eb8e3864ea49e918a5dbe6e4c9d06a4292c104a792"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 2A 8B 45 0C 0F B6 00 84 C0 74 17 8B 45 0C 40 89 44 24 04 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_71e487ea {
    meta:
        author = "Elastic Security"
        id = "71e487ea-a592-469c-a03e-0c64d2549e74"
        fingerprint = "8df69968ddfec5821500949015192b6cdbc188c74f785a272effd7bc9707f661"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "b8d044f2de21d20c7e4b43a2baf5d8cdb97fba95c3b99816848c0f214515295b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E0 8B 45 D8 8B 04 D0 8D 50 01 83 EC 0C 8D 85 40 FF FF FF 50 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6620ec67 {
    meta:
        author = "Elastic Security"
        id = "6620ec67-8f12-435b-963c-b44a02f43ef1"
        fingerprint = "9d68db5b3779bb5abe078f9e36dd9a09d4d3ad9274a3a50bdfa0e444a7e46623"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "b91eb196605c155c98f824abf8afe122f113d1fed254074117652f93d0c9d6b2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { AF 93 64 1A D8 0B 48 93 64 0B 48 A3 64 11 D1 0B 41 05 E4 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d996d335 {
    meta:
        author = "Elastic Security"
        id = "d996d335-e049-4052-bf36-6cd07c911a8b"
        fingerprint = "e9ccb8412f32187c309b0e9afcc3a6da21ad2f1ffa251c27f9f720ccb284e3ac"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "b511eacd4b44744c8cf82d1b4a9bc6f1022fe6be7c5d17356b171f727ddc6eda"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D0 EB 0F 40 38 37 75 04 48 89 F8 C3 49 FF C8 48 FF C7 4D 85 C0 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d0c57a2e {
    meta:
        author = "Elastic Security"
        id = "d0c57a2e-c10c-436c-be13-50a269326cf2"
        fingerprint = "3ee7d3a33575ed3aa7431489a8fb18bf30cfd5d6c776066ab2a27f93303124b6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 07 0F B6 57 01 C1 E0 08 09 D0 89 06 0F BE 47 02 C1 E8 1F 89 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_751acb94 {
    meta:
        author = "Elastic Security"
        id = "751acb94-cb23-4949-a4dd-87985c47379e"
        fingerprint = "dbdfdb455868332e9fbadd36c084d0927a3dd8ab844f0b1866e914914084cd4b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 54 6F 20 43 6F 6E 6E 65 63 74 21 20 00 53 75 63 63 65 73 66 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_656bf077 {
    meta:
        author = "Elastic Security"
        id = "656bf077-ca0c-4d28-9daa-eb6baafaf467"
        fingerprint = "3ea8ed60190198d5887bb7093975d648a9fd78234827d648a8258008c965b1c1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 28 48 8B 45 E8 0F B6 00 84 C0 74 14 48 8B 75 E8 48 FF C6 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_e6d75e6f {
    meta:
        author = "Elastic Security"
        id = "e6d75e6f-aa04-4767-8730-6909958044a7"
        fingerprint = "e99805e8917d6526031270b6da5c2f3cc1c8235fed1d47134835a107d0df497c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "48b15093f33c18778724c48c34199a420be4beb0d794e36034097806e1521eb8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 CD 80 C3 8B 54 24 04 8B 4C 24 08 87 D3 B8 5B 00 00 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_7167d08f {
    meta:
        author = "Elastic Security"
        id = "7167d08f-bfeb-4d78-9783-3a1df2ef0ed3"
        fingerprint = "b9df4ab322a2a329168f684b07b7b05ee3d03165c5b9050a4710eae7aeca6cd9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0C 8A 00 3C 2D 75 13 FF 45 0C C7 45 E4 01 00 00 00 EB 07 FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_27de1106 {
    meta:
        author = "Elastic Security"
        id = "27de1106-497d-40a0-8fc4-929f7a927628"
        fingerprint = "9a747f0fc7ccc55f24f2654344484f643103da709270a45de4c1174d8e4101cc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0C 0F B6 00 84 C0 74 18 8B 45 0C 40 8B 55 08 42 89 44 24 04 89 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_148b91a2 {
    meta:
        author = "Elastic Security"
        id = "148b91a2-ed51-4c2d-9d15-6a48d9ea3e0a"
        fingerprint = "0f75090ed840f4601df4e43a2f49f2b32585213f3d86d19fb255d79c21086ba3"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "d5b2bde0749ff482dc2389971e2ac76c4b1e7b887208a538d5555f0fe6984825"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C6 45 DB FC EB 04 C6 45 DB FE 0F B6 45 DB 88 45 FF 48 8D 75 FF 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_20f5e74f {
    meta:
        author = "Elastic Security"
        id = "20f5e74f-9f94-431b-877c-9b0d78a1d4eb"
        fingerprint = "070fe0d678612b4ec8447a07ead0990a0abd908ce714388720e7fd7055bf1175"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "9084b00f9bb71524987dc000fb2bc6f38e722e2be2832589ca4bb1671e852f5b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D8 8B 45 D0 8B 04 D0 8D 50 01 83 EC 0C 8D 85 38 FF FF FF 50 8D 85 40 FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_1b2e2a3a {
    meta:
        author = "Elastic Security"
        id = "1b2e2a3a-1302-41c7-be99-43edb5563294"
        fingerprint = "6f24b67d0a6a4fc4e1cfea5a5414b82af1332a3e6074eb2178aee6b27702b407"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 7D 18 00 74 25 8B 45 1C 83 E0 02 85 C0 74 1B C7 44 24 04 2D 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_620087b9 {
    meta:
        author = "Elastic Security"
        id = "620087b9-c87d-4752-89e8-ca1c16486b28"
        fingerprint = "06cd7e6eb62352ec2ccb9ed48e58c0583c02fefd137cd048d053ab30b5330307"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 89 D8 48 83 C8 01 EB 04 48 8B 76 10 48 3B 46 08 72 F6 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_dd0d6173 {
    meta:
        author = "Elastic Security"
        id = "dd0d6173-b863-45cf-9348-3375a4e624cf"
        fingerprint = "5e2cb111c2b712951b71166111d339724b4f52b93f90cb474f1e67598212605f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 F8 8B 45 F0 89 42 0C 48 8B 55 F8 8B 45 F4 89 42 10 C9 C3 55 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_779e142f {
    meta:
        author = "Elastic Security"
        id = "779e142f-b867-46e6-b1fb-9105976f42fd"
        fingerprint = "83377b6fa77fda4544c409487d2d2c1ddcef8f7d4120f49a18888c7536f3969f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EC 8B 45 E8 83 E0 02 85 C0 74 07 C7 45 D8 30 00 00 00 8B 45 E8 83 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_cf84c9f2 {
    meta:
        author = "Elastic Security"
        id = "cf84c9f2-7435-4faf-8c5f-d14945ffad7a"
        fingerprint = "bb766b356c3e8706740e3bb9b4a7171d8eb5137e09fc7ab6952412fa55e2dcfc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 48 89 E5 48 83 EC 30 48 89 7D E8 89 75 E4 89 55 E0 C7 45 F8 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_0cd591cd {
    meta:
        author = "Elastic Security"
        id = "0cd591cd-c348-4c3a-a895-2063cf892cda"
        fingerprint = "96c4ff70729ddb981adafd8c8277649a88a87e380d2f321dff53f0741675fb1b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4E F8 48 8D 4E D8 49 8D 42 E0 48 83 C7 03 EB 6B 4C 8B 46 F8 48 8D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_33b4111a {
    meta:
        author = "Elastic Security"
        id = "33b4111a-e59e-48db-9d74-34ca44fcd9f5"
        fingerprint = "9c3b63b9a0f54006bae12abcefdb518904a85f78be573f0780f0a265b12d2d6e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C1 83 E1 0F 74 1A B8 10 00 00 00 48 29 C8 48 8D 0C 02 48 89 DA 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_4f43b164 {
    meta:
        author = "Elastic Security"
        id = "4f43b164-686d-4b73-b532-45e2df992b33"
        fingerprint = "35a885850a06e7991c3a8612bbcdfc279b87e4ca549723192d3011a1e0a81640"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "f0fdb3de75f85e199766bbb39722865cac578cde754afa2d2f065ef028eec788"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 46 00 4B 49 4C 4C 53 55 42 00 4B 49 4C 4C 53 55 42 20 3C 73 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_e4a1982b {
    meta:
        author = "Elastic Security"
        id = "e4a1982b-928a-4da5-b497-cedc1d26e845"
        fingerprint = "d9f852c28433128b0fd330bee35f7bd4aada5226e9ca865fe5cd8cca52b2a622"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 EC F7 D0 21 D0 33 45 FC C9 C3 55 48 89 E5 48 83 EC 30 48 89 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_862c4e0e {
    meta:
        author = "Elastic Security"
        id = "862c4e0e-83a4-458b-8c00-f2f3cf0bf9db"
        fingerprint = "2a6b4f8d8fb4703ed26bdcfbbb5c539dc451c8b90649bee80015c164eae4c281"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "9526277255a8d632355bfe54d53154c9c54a4ab75e3ba24333c73ad0ed7cadb1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 02 89 45 F8 8B 45 F8 C1 E8 10 85 C0 75 E6 8B 45 F8 F7 D0 0F }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9127f7be {
    meta:
        author = "Elastic Security"
        id = "9127f7be-6e82-46a1-9f11-0b3570b0cd76"
        fingerprint = "72c742cb8b11ddf030e10f67e13c0392748dcd970394ec77ace3d2baa705a375"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E4 F7 E1 89 D0 C1 E8 03 89 45 E8 8B 45 E8 01 C0 03 45 E8 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_0e03b7d3 {
    meta:
        author = "Elastic Security"
        id = "0e03b7d3-a6b0-46a0-920e-c15ee7e723f7"
        fingerprint = "1bf1f271005328669b3eb4940e2b75eff9fc47208d79a12196fd7ce04bc4dbe8"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F5 74 84 32 63 29 5A B2 78 FF F7 FA 0E 51 B3 2F CD 7F 10 FA }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_32eb0c81 {
    meta:
        author = "Elastic Security"
        id = "32eb0c81-25af-4670-ab77-07ea7ce1874a"
        fingerprint = "7c50ed29e2dd75a6a85afc43f8452794cb787ecd2061f4bf415d7038c14c523f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D4 48 FF 45 F0 48 8B 45 F0 0F B6 00 84 C0 75 DB EB 12 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9abf7e0c {
    meta:
        author = "Elastic Security"
        id = "9abf7e0c-5076-4881-a488-f0f62810f843"
        fingerprint = "7d02513aaef250091a58db58435a1381974e55c2ed695c194b6b7b83c235f848"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 E0 0F B6 42 0D 83 C8 01 88 42 0D 48 8B 55 E0 0F B6 42 0D 83 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_33801844 {
    meta:
        author = "Elastic Security"
        id = "33801844-50b1-4968-a1b7-d106f16519ee"
        fingerprint = "36218345b9ce4aaf50b5df1642c00ac5caa744069e952eb6008a9a57a37dbbdc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "2ceff60e88c30c02c1c7b12a224aba1895669aad7316a40b575579275b3edbb3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 F8 48 83 E8 01 0F B6 00 3C 0D 75 0B 48 8B 45 F8 0F B6 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a33a8363 {
    meta:
        author = "Elastic Security"
        id = "a33a8363-5511-4fe1-a0d8-75156b9ccfc7"
        fingerprint = "74f964eaadbf8f30d40cdec40b603c5141135d2e658e7ce217d0d6c62e18dd08"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 88 02 48 85 D2 75 ED 5A 5B 5D 41 5C 41 5D 4C 89 F0 41 5E }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9a62845f {
    meta:
        author = "Elastic Security"
        id = "9a62845f-6311-49ae-beac-f446b2909d9c"
        fingerprint = "2ccc813c5efed35308eb2422239b5b83d051eca64b7c785e66d602b13f8bd9b4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "f67f8566beab9d7494350923aceb0e76cd28173bdf2c4256e9d45eff7fc8cb41"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 83 F8 20 7F 1E 83 7D 08 07 75 33 8B 45 0C 83 C0 18 8B 00 83 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_4d81ad42 {
    meta:
        author = "Elastic Security"
        id = "4d81ad42-bf08-48a9-9a93-85cb491257b3"
        fingerprint = "f285683c3b145990e1b6d31d3c9d09177ebf76f183d0fa336e8df3dbcba24366"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "3021a861e6f03df3e7e3919e6255bdae6e48163b9a8ba4f1a5c5dced3e3e368b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 44 C8 07 0B BF F1 1B 7E 83 CD FF 31 DB 2E 22 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6a510422 {
    meta:
        author = "Elastic Security"
        id = "6a510422-3662-4fdb-9c03-0101f16e87cd"
        fingerprint = "8ee116ff41236771cdc8dc4b796c3b211502413ae631d5b5aedbbaa2eccc3b75"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0B E5 24 30 1B E5 2C 30 0B E5 1C 00 00 EA 18 30 1B E5 00 30 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d2953f92 {
    meta:
        author = "Elastic Security"
        id = "d2953f92-62ee-428d-88c5-723914c88c6e"
        fingerprint = "276c6d62a8a335d0e2421b6b5b90c2c0eb69eec294bc9fcdeb7743abbf08d8bc"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 1B E5 2A 00 53 E3 0A 00 00 0A 30 30 1B E5 3F 00 53 E3 23 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6ae4b580 {
    meta:
        author = "Elastic Security"
        id = "6ae4b580-f7cf-4318-b584-7ea15f10f5ea"
        fingerprint = "279e344d6da518980631e70d7b1ded4ff1b034d24e4b4fe01b36ed62f5c1176c"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 30 0B E5 3C 20 1B E5 6C 32 1B E5 03 00 52 E1 01 00 00 DA 6C }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d608cf3b {
    meta:
        author = "Elastic Security"
        id = "d608cf3b-c255-4a8d-9bf1-66f92eacd751"
        fingerprint = "3825aa1c9cddb46fdef6abc0503b42acbca8744dd89b981a3eea8db2f86a8a76"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF 2F E1 7E 03 00 00 78 D8 00 00 24 00 00 00 28 00 00 00 4C }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_3f8cf56e {
    meta:
        author = "Elastic Security"
        id = "3f8cf56e-a8cb-4c03-8829-f1daa3dc64a8"
        fingerprint = "77306f0610515434371f70f2b42c895cdc5bbae2ef6919cf835b3cfe2e4e4976"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "1878f0783085cc6beb2b81cfda304ec983374264ce54b6b98a51c09aea9f750d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 2F DA E8 E9 CC E4 F4 39 55 E2 9E 33 0E C0 F0 FB 26 93 31 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_fb14e81f {
    meta:
        author = "Elastic Security"
        id = "fb14e81f-be2a-4428-9877-958e394a7ae2"
        fingerprint = "12b430108256bd0f57f48b9dbbea12eba7405c0b3b66a1c4b882647051f1ec52"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "0fd07e6068a721774716eb4940e2c19faef02d5bdacf3b018bf5995fa98a3a27"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4E 45 52 00 53 43 41 4E 4E 45 52 20 4F 4E 20 7C 20 4F 46 46 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_e09726dc {
    meta:
        author = "Elastic Security"
        id = "e09726dc-4e6d-4115-b178-d20375c09e04"
        fingerprint = "614d54b3346835cd5c2a36a54cae917299b1a1ae0d057e3fa1bb7dddefc1490f"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "1e64187b5e3b5fe71d34ea555ff31961404adad83f8e0bd1ce0aad056a878d73"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 48 83 EC 08 48 83 C4 08 C3 00 00 00 01 00 02 00 50 49 4E 47 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_ad12b9b6 {
    meta:
        author = "Elastic Security"
        id = "ad12b9b6-2e66-4647-8bf3-0300f2124a97"
        fingerprint = "46d86406f7fb25f0e240abc13e86291c56eb7468d0128fdff181f28d4f978058"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "f0411131acfddb40ac8069164ce2808e9c8928709898d3fb5dc88036003fe9c8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4C 52 46 00 4B 45 46 31 4A 43 53 00 4B 45 46 31 51 45 42 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_0535ebf7 {
    meta:
        author = "Elastic Security"
        id = "0535ebf7-844f-4207-82ef-e155ceff7a3e"
        fingerprint = "2b9b17dad296c0a58a7efa1fb3f71c62bf849f00deb978c1103ab8a480290024"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "77e18bb5479b644ba01d074057c9e2bd532717f6ab3bb88ad2b7497b85d2a5de"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 48 8B 04 24 6A 18 48 F7 14 24 48 FF 04 24 48 03 24 24 48 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_32a7edd2 {
    meta:
        author = "Elastic Security"
        id = "32a7edd2-175f-45b3-bf3d-8c842e4ae7e7"
        fingerprint = "d59183e8833272440a12b96de82866171f7ea0212cee0e2629c169fdde4da2a5"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 75 FD 48 FD 45 FD 0F FD 00 FD FD 0F FD FD 02 00 00 48 FD 45 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d7f35b54 {
    meta:
        author = "Elastic Security"
        id = "d7f35b54-82a8-4ef0-8c8c-30a6734223e1"
        fingerprint = "d01db0f6a169d82d921c76801738108a2f0ef4ef65ea2e104fb80188a3bb73b8"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FD 48 FD 45 FD 48 FD FD FD FD FD FD FD FD FD 48 FD 45 FD 66 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_f11e98be {
    meta:
        author = "Elastic Security"
        id = "f11e98be-bf81-480e-b2d1-dcc748c6869d"
        fingerprint = "8cdf2acffd0cdce48ceaffa6682d2f505c557b873e4f418f4712dfa281a3095a"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FD 40 00 09 FD 21 FD FD 08 48 FD 80 3E 00 75 FD FD 4C 24 48 0F FD }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_8d4e4f4a {
    meta:
        author = "Elastic Security"
        id = "8d4e4f4a-b3ea-4f93-ada2-2c88bb5d806d"
        fingerprint = "9601c7cf7f2b234bc30d00e1fc0217b5fa615c369e790f5ff9ca42bcd85aea12"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 50 00 FD FD 00 00 00 31 FD 48 FD FD 01 00 00 00 49 FD FD 04 }
    condition:
        all of them
}

