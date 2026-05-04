rule Linux_Trojan_Iroffer_53692410 {
    meta:
        author = "Elastic Security"
        id = "53692410-4213-4550-890e-4c62867937bc"
        fingerprint = "f070ee35ad42d9d30021cc2796cfd2859007201c638f98f42fdbec25c53194fb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "e76508141970efb3e4709bcff83772da9b10169c599e13e58432257a7bb2defa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 69 6E 67 20 55 6E 6B 6E 6F 77 6E 20 4D 73 67 6C 6F 67 20 54 61 67 }
    condition:
        all of them
}

rule Linux_Trojan_Iroffer_013e07de {
    meta:
        author = "Elastic Security"
        id = "013e07de-95bd-4774-a14f-0a10f911a2dd"
        fingerprint = "92dde62076acec29a637b63a35f00c35f706df84d6ee9cabda0c6f63d01a13c4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "e76508141970efb3e4709bcff83772da9b10169c599e13e58432257a7bb2defa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 49 67 6E 6F 72 69 6E 67 20 42 61 64 20 58 44 43 43 20 4E 6F }
    condition:
        all of them
}

rule Linux_Trojan_Iroffer_0de95cab {
    meta:
        author = "Elastic Security"
        id = "0de95cab-c671-44f0-a85e-5a5634e906f7"
        fingerprint = "42c1ab8af313ec3c475535151ee67cac93ab6a25252b52b1e09c166065fb2760"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "717bea3902109d1b1d57e57c26b81442c0705af774139cd73105b2994ab89514"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 41 52 52 45 43 4F 52 44 53 00 53 68 6F 77 20 49 6E 66 6F }
    condition:
        all of them
}

rule Linux_Trojan_Iroffer_711259e4 {
    meta:
        author = "Elastic Security"
        id = "711259e4-f081-4d81-8257-60ba733354c5"
        fingerprint = "aca63ef57ab6cb5579a2a5fea6095d88a3a4fb8347353febb3d02cc88a241b78"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "e76508141970efb3e4709bcff83772da9b10169c599e13e58432257a7bb2defa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 03 7E 2B 8B 45 C8 3D FF 00 00 00 77 21 8B 55 CC 81 FA FF 00 }
    condition:
        all of them
}

rule Linux_Trojan_Iroffer_7478ddd9 {
    meta:
        author = "Elastic Security"
        id = "7478ddd9-ebb6-4bd4-a1ad-d0bf8f99ab1d"
        fingerprint = "b497ee116b77e2ba1fedfad90894d956806a2ffa19cadc33a916513199b0a381"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "20e1509c23d7ef14b15823e4c56b9a590e70c5b7960a04e94b662fc34152266c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 80 FA 0F 74 10 80 FA 16 74 0B 80 FA 1F 74 06 C6 04 1E 2E 89 }
    condition:
        all of them
}

