rule MacOS_Trojan_Bundlore_28b13e67 {
    meta:
        author = "Elastic Security"
        id = "28b13e67-e01c-45eb-aae6-ecd02b017a44"
        fingerprint = "1e85be4432b87214d61e675174f117e36baa8ab949701ee1d980ad5dd8454bac"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "0b50a38749ea8faf571169ebcfce3dfd668eaefeb9a91d25a96e6b3881e4a3e8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 05 A5 A3 A9 37 D2 05 13 E9 3E D6 EA 6A EC 9B DC 36 E5 76 A7 53 B3 0F 06 46 D1 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_75c8cb4e {
    meta:
        author = "Elastic Security"
        id = "75c8cb4e-f8bd-4a2c-8a5e-8500e12a9030"
        fingerprint = "db68c315dba62f81168579aead9c5827f7bf1df4a3c2e557b920fa8fbbd6f3c2"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "3d69912e19758958e1ebdef5e12c70c705d7911c3b9df03348c5d02dd06ebe4e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 EE 19 00 00 EA 80 35 E8 19 00 00 3B 80 35 E2 19 00 00 A4 80 35 DC 19 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_17b564b4 {
    meta:
        author = "Elastic Security"
        id = "17b564b4-7452-473f-873f-f907b5b8ebc4"
        fingerprint = "7701fab23d59b8c0db381a1140c4e350e2ce24b8114adbdbf3c382c6d82ea531"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "94f6e5ee6eb3a191faaf332ea948301bbb919f4ec6725b258e4f8e07b6a7881d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 D9 11 00 00 05 80 35 D3 11 00 00 2B 80 35 CD 11 00 00 F6 80 35 C7 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_c90c088a {
    meta:
        author = "Elastic Security"
        id = "c90c088a-abf5-4e52-a69e-5a4fd4b5cf15"
        fingerprint = "c2300895f8ff5ae13bc0ed93653afc69b30d1d01f5ce882bd20f2b65426ecb47"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "875513f4ebeb63b9e4d82fb5bff2b2dc75b69c0bfa5dd8d2895f22eaa783f372"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 E1 11 00 00 92 80 35 DB 11 00 00 2A 80 35 D5 11 00 00 7F 80 35 CF 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_3965578d {
    meta:
        author = "Elastic Security"
        id = "3965578d-3180-48e4-b5be-532e880b1df9"
        fingerprint = "e41f08618db822ba5185e5dc3f932a72e1070fbb424ff2c097cab5e58ad9e2db"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "d72543505e36db40e0ccbf14f4ce3853b1022a8aeadd96d173d84e068b4f68fa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 33 2A 00 00 60 80 35 2D 2A 00 00 D0 80 35 27 2A 00 00 54 80 35 21 2A 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_00d9d0e9 {
    meta:
        author = "Elastic Security"
        id = "00d9d0e9-28d8-4c32-bc6f-52008ee69b07"
        fingerprint = "7dcc6b124d631767c259101f36b4bbd6b9d27b2da474d90e31447ea03a2711a6"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "73069b34e513ff1b742b03fed427dc947c22681f30cf46288a08ca545fc7d7dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 8E 11 00 00 55 80 35 88 11 00 00 BC 80 35 82 11 00 00 72 80 35 7C 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_650b8ff4 {
    meta:
        author = "Elastic Security"
        id = "650b8ff4-6cc8-4bfc-ba01-ac9c86410ecc"
        fingerprint = "4f4691f6830684a71e7b3ab322bf6ec4638bf0035adf3177dbd0f02e54b3fd80"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "78fd2c4afd7e810d93d91811888172c4788a0a2af0b88008573ce8b6b819ae5a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 8B 11 00 00 60 80 35 85 11 00 00 12 80 35 7F 11 00 00 8C 80 35 79 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_c8ad7edd {
    meta:
        author = "Elastic Security"
        id = "c8ad7edd-4233-44ce-a4e5-96dfc3504f8a"
        fingerprint = "c6a8a1d9951863d4277d297dd6ff8ad7b758ca2dfe16740265456bb7bb0fd7d0"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "d4915473e1096a82afdaee405189a0d0ae961bd11a9e5e9adc420dd64cb48c24"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 74 11 00 00 D5 80 35 6E 11 00 00 57 80 35 68 11 00 00 4C 80 35 62 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_cb7344eb {
    meta:
        author = "Elastic Security"
        id = "cb7344eb-51e6-4f17-a5d4-eea98938945b"
        fingerprint = "6041c50c9eefe9cafb8768141cd7692540f6af2cdd6e0a763b7d7e50b8586999"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "53373668d8c5dc17f58768bf59fb5ab6d261a62d0950037f0605f289102e3e56"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 ED 09 00 00 92 80 35 E7 09 00 00 93 80 35 E1 09 00 00 16 80 35 DB 09 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_753e5738 {
    meta:
        author = "Elastic Security"
        id = "753e5738-0c72-4178-9396-d1950e868104"
        fingerprint = "c0a41a8bc7fbf994d3f5a5d6c836db3596b1401b0e209a081354af2190fcb3c2"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "42aeea232b28724d1fa6e30b1aeb8f8b8c22e1bc8afd1bbb4f90e445e31bdfe9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 9A 11 00 00 96 80 35 94 11 00 00 68 80 35 8E 11 00 00 38 80 35 88 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_7b9f0c28 {
    meta:
        author = "Elastic Security"
        id = "7b9f0c28-181d-4fdc-8a57-467d5105129a"
        fingerprint = "dde16fdd37a16fa4dae24324283cd4b36ed2eb78f486cedd1a6c7bef7cde7370"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "fc4da125fed359d3e1740dafaa06f4db1ffc91dbf22fd5e7993acf8597c4c283"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 B6 15 00 00 81 80 35 B0 15 00 00 14 80 35 AA 15 00 00 BC 80 35 A4 15 00 00 }
    condition:
        all of them
}

