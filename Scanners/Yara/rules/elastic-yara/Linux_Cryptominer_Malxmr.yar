rule Linux_Cryptominer_Malxmr_d13544d7 {
    meta:
        author = "Elastic Security"
        id = "d13544d7-4834-4ce7-9339-9c933ee51b2c"
        fingerprint = "02e1be4a7073e849b183851994c83f1f2077fe74cbcdd0b3066999d0c9499a09"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "85fa30ba59602199fd99463acf50bd607e755c2e18cd8843ffcfb6b1aca24bb3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 51 50 4D 21 EB 4B 8D 0C 24 4C 89 54 24 90 4C 89 DD 48 BA AA AA AA AA AA AA }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_ad09e090 {
    meta:
        author = "Elastic Security"
        id = "ad09e090-098e-461d-b967-e45654b902bb"
        fingerprint = "a62729bbe04eca01dbb3c56de63466ed115f30926fc5d203c9bae75a93227e09"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "cdd3d567fbcbdd6799afad241ae29acbe4ab549445e5c4fc0678d16e75b40dfa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 50 8B 44 24 64 89 54 24 54 39 C3 77 0E 72 08 8B 44 24 60 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_12299814 {
    meta:
        author = "Elastic Security"
        id = "12299814-c916-4cad-a627-f8b082f5643d"
        fingerprint = "b626f04a8648b0f42564df9c2ef3989e602d1307b18256e028450c495dc15260"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "eb3802496bd2fef72bd2a07e32ea753f69f1c2cc0b5a605e480f3bbb80b22676"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 3C 40 00 83 C4 10 89 44 24 04 80 7D 00 00 74 97 83 EC 0C 89 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_a47b77e4 {
    meta:
        author = "Elastic Security"
        id = "a47b77e4-0d8d-4714-8527-7b783f0f27b8"
        fingerprint = "635a35defde186972cd6626bd75a1e557a1a9008ab93b38ef1a3635b3210354b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "995b43ccb20343494e314824343a567fd85f430e241fdeb43704d9d4937d76cc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8D 48 49 5E 97 87 DC 73 86 19 51 B3 36 1A 6E FC 8C CC 2C 6E 0B }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_21d0550b {
    meta:
        author = "Elastic Security"
        id = "21d0550b-4f15-4481-ba9c-2be26ea8f81a"
        fingerprint = "5b556d2e3e48fda57c741c4c7b9efb72aad579e5055df366cdb9cfa38e496494"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "07db41a4ddaac802b04df5e5bbae0881fead30cb8f6fa53a8a2e1edf14f2d36b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 3B 31 C0 48 83 C9 FF 48 89 EE F2 AE 48 8B 3B 48 F7 D1 48 FF C9 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_c8adb449 {
    meta:
        author = "Elastic Security"
        id = "c8adb449-3de5-4cdd-9b62-fe4bcbe82394"
        fingerprint = "838950826835e811eb7ea3af7a612b4263d171ded4761d2b547a4012adba4028"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "00ec7a6e9611b5c0e26c148ae5ebfedc57cf52b21e93c2fe3eac85bf88edc7ea"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D2 4C 89 54 24 A0 4C 89 FA 48 F7 D2 48 23 54 24 88 49 89 D2 48 8B 54 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_bcab1e8f {
    meta:
        author = "Elastic Security"
        id = "bcab1e8f-8a8f-4309-8e47-416861d1894c"
        fingerprint = "2106f2ba97c75468a2f25d1266053791034ff9a15d57df1ba3caf21f74b812f7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "19df7fd22051abe3f782432398ea30f8be88cf42ef14bc301b1676f35b37cd7e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EB D9 D3 0B EB D5 29 0B EB D1 03 48 6C 01 0B EB CA 0F AF 0B }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_6671f33a {
    meta:
        author = "Elastic Security"
        id = "6671f33a-03bb-40d8-b439-64a66082457d"
        fingerprint = "cb178050ee351059b083c6a71b5b1b6a9e0aa733598a05b3571701949b4e6b28"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "85fa30ba59602199fd99463acf50bd607e755c2e18cd8843ffcfb6b1aca24bb3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4D 18 48 01 4B 18 5A 5B 5D C3 83 C8 FF C3 48 85 FF 49 89 F8 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_74418ec5 {
    meta:
        author = "Elastic Security"
        id = "74418ec5-f84a-4d79-b1b0-c1d579ad7b97"
        fingerprint = "ec14cac86b2b0f75f1d01b7fb4b57bfa3365f8e4d11bfed2707b0174875d1234"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "d79ad967ac9fc0b1b6d54e844de60d7ba3eaad673ee69d30f9f804e5ccbf2880"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F9 75 7A A8 8A 65 FC 5C E0 6E 09 4B 8F AA B3 A4 66 44 B1 D1 13 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_979160f6 {
    meta:
        author = "Elastic Security"
        id = "979160f6-402a-4e4b-858a-374c9415493b"
        fingerprint = "fb933702578e2cf7e8ad74554ef93c07b610d6da8bc5743cbf86c363c1615f40"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E0 08 C1 ED 10 41 31 C3 89 D8 45 09 D0 C1 E8 10 C1 E3 10 41 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_fe7139e5 {
    meta:
        author = "Elastic Security"
        id = "fe7139e5-3c8e-422c-aaf7-e683369d23d4"
        fingerprint = "4af38ca3ec66ca86190e6196a9a4ba81a0a2b77f88695957137f6cda8fafdec9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "8b13dc59db58b6c4cd51abf9c1d6f350fa2cb0dbb44b387d3e171eacc82a04de"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF 74 5B 48 29 F9 49 89 DC 4C 8D 69 01 49 D1 ED 4C 01 E9 4D 8D 6C }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_f35a670c {
    meta:
        author = "Elastic Security"
        id = "f35a670c-7599-4c93-b08b-463c4a93808a"
        fingerprint = "9064024118d30d89bdc093d5372a0d9fefd43eb1ac6359dbedcf3b73ba93f312"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "a73808211ba00b92f8d0027831b3aa74db15f068c53dd7f20fcadb294224f480"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4C 01 CD 48 0F AF D6 48 8D 54 55 00 89 DD 48 31 D7 48 C1 C7 20 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_70e5946e {
    meta:
        author = "Elastic Security"
        id = "70e5946e-3e73-4b07-9e7d-af036a3242f9"
        fingerprint = "ced6885fda17c862753232fde3e7e8797f5a900ebab7570b78aa7138a0068eb9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4F 70 48 8D B4 24 B0 00 00 00 48 89 34 CA 49 8B 57 68 48 89 C8 83 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_033f06dd {
    meta:
        author = "Elastic Security"
        id = "033f06dd-f3ed-4140-bbff-138ed2d8378c"
        fingerprint = "2f1f39e10df0ca6c133237b6d92afcb8a9c23de511120e8860c1e6ed571252ed"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "3afc8d2d85aca61108d21f82355ad813eba7a189e81dde263d318988c5ea50bd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 42 68 63 33 4E 33 5A 48 78 6A 64 58 51 67 4C 57 51 36 49 43 31 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_ce0c185f {
    meta:
        author = "Elastic Security"
        id = "ce0c185f-fca2-47d3-9e7c-57b541af98a5"
        fingerprint = "0d2e3e2b04e93f25c500677482e15d92408cb1da2a5e3c5a13dc71e52d140f85"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "cdd3d567fbcbdd6799afad241ae29acbe4ab549445e5c4fc0678d16e75b40dfa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EF E5 66 0F 6F AC 24 80 00 00 00 66 0F EB E8 66 0F EF D5 66 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_da08e491 {
    meta:
        author = "Elastic Security"
        id = "da08e491-c6fa-4228-8b6a-8adae2f0324a"
        fingerprint = "c4911fdeece4c3f97bbc9ef4da478c5f5363ab71a70b0767edec0f94b87fd939"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "4638d9ece32cd1385121146378772d487666548066aecd7e40c3ba5231f54cc0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F9 48 31 CD 48 89 F9 48 F7 D1 4C 21 F9 48 21 DA 49 31 CA 48 }
    condition:
        all of them
}

