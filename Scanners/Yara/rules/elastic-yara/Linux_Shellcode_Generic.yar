rule Linux_Shellcode_Generic_5669055f {
    meta:
        author = "Elastic Security"
        id = "5669055f-8ce7-4163-af06-cb265fde3eef"
        fingerprint = "616fe440ff330a1d22cacbdc2592c99328ea028700447724d2d5b930554a22f4"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "87ef4def16d956cdfecaea899cbb55ff59a6739bbb438bf44a8b5fec7fcfd85b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 31 C0 31 DB 31 C9 B0 17 CD 80 31 C0 51 B1 06 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_d2c96b1d {
    meta:
        author = "Elastic Security"
        id = "d2c96b1d-f424-476c-9463-dd34a1da524e"
        fingerprint = "ee042895d863310ff493fdd33721571edd322e764a735381d236b2c0a7077cfa"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "403d53a65bd77856f7c565307af5003b07413f2aba50869655cdd88ce15b0c82"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E1 8D 54 24 04 5B B0 0B CD 80 31 C0 B0 01 31 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_30c70926 {
    meta:
        author = "Elastic Security"
        id = "30c70926-9414-499a-a4db-7c3bb902dd82"
        fingerprint = "4af586211c56e92b1c60fcd09b4def9801086fbe633418459dc07839fe9c735a"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "a742e23f26726293b1bff3db72864471d6bb4062db1cc6e1c4241f51ec0e21b1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E3 52 53 89 E1 31 C0 B0 0B CD 80 31 C0 40 CD 80 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_224bdcc4 {
    meta:
        author = "Elastic Security"
        id = "224bdcc4-4b38-44b5-96c6-d3b378628fa4"
        fingerprint = "e23b239775c321d4326eff2a7edf0787116dd6d8a9e279657e4b2b01b33e72aa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "bd22648babbee04555cef52bfe3e0285d33852e85d254b8ebc847e4e841b447e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E6 6A 10 5A 6A 2A 58 0F 05 48 85 C0 79 1B 49 FF C9 74 22 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_99b991cd {
    meta:
        author = "Elastic Security"
        id = "99b991cd-a5ca-475c-8c10-e43b9d22d26e"
        fingerprint = "ed904a3214ccf43482e3ddf75f3683fea45f7c43a2f1860bac427d7d15d8c399"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "954b5a073ce99075b60beec72936975e48787bea936b4c5f13e254496a20d81d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6E 89 E3 50 53 89 E1 B0 0B CD 80 00 4C 65 6E 67 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_24b9aa12 {
    meta:
        author = "Elastic Security"
        id = "24b9aa12-92b2-492d-9a0e-078cdab5830a"
        fingerprint = "0ded0ad2fdfff464bf9a0b5a59b8edfe1151a513203386daae6f9f166fd48e5c"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "24b2c1ccbbbe135d40597fbd23f7951d93260d0039e0281919de60fa74eb5977"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6E 89 E3 89 C1 89 C2 B0 0B CD 80 31 C0 40 CD 80 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_8ac37612 {
    meta:
        author = "Elastic Security"
        id = "8ac37612-aec8-4376-8269-2594152ced8a"
        fingerprint = "97a3d3e7ff4c9ae31f71e609d10b3b848cb0390ae2d1d738ef53fd23ff0621bc"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "c199b902fa4b0fcf54dc6bf3e25ad16c12f862b47e055863a5e9e1f98c6bd6ca"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E3 ?? 53 89 E1 B0 0B CD 80 00 47 43 43 3A }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_932ed0f0 {
    meta:
        author = "Elastic Security"
        id = "932ed0f0-bd43-4367-bcc3-ecd8f65b52ee"
        fingerprint = "7aa4619d2629b5d795e675d17a6e962c6d66a75e11fa884c0b195cb566090070"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "f357597f718f86258e7a640250f2e9cf1c3363ab5af8ddbbabb10ebfa3c91251"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E3 50 89 E2 53 89 E1 B0 0B CD 80 31 C0 40 CD 80 }
    condition:
        all of them
}

