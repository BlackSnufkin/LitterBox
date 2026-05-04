rule Linux_Trojan_Ngioweb_8bd3002c {
    meta:
        author = "Elastic Security"
        id = "8bd3002c-d9c7-4f93-b7f0-4cb9ba131338"
        fingerprint = "2ee5432cf6ead4eca3aad70e40fac7e182bdcc74dc22dc91a12946ae4182f1ab"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 18 67 8A 09 84 C9 74 0D 80 F9 2E 75 02 FF C0 FF 44 24 18 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_a592a280 {
    meta:
        author = "Elastic Security"
        id = "a592a280-053f-47bc-8d74-3fa5d74bd072"
        fingerprint = "60f5ddd115fa1abac804d2978bbb8d70572de0df9da80686b5652520c03bd1ee"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 75 06 8B 7C 24 2C EB 2C 83 FD 01 75 06 8B 7C 24 3C EB 21 83 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_d57aa841 {
    meta:
        author = "Elastic Security"
        id = "d57aa841-8eb5-4765-9434-233ab119015f"
        fingerprint = "83a4eb7c8ac42097d3483bcf918823105b4ea4291a566b4184eacc2a0f3aa3a4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "555d60bd863caff231700c5f606d0034d5aa8362862d1fd0c816615d59f582f7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 0C 48 89 4C 24 10 4C 89 44 24 18 66 83 F8 02 74 10 BB 10 00 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_b97e0253 {
    meta:
        author = "Elastic Security"
        id = "b97e0253-497f-4c2c-9d4c-ad89af64847f"
        fingerprint = "859f29acec8bb05b8a8e827af91e927db0b2390410179a0f5b03e7f71af64949"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 5C 41 5D 41 5E 41 5F C3 67 0F BE 17 39 F2 74 12 84 D2 74 04 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_66c465a0 {
    meta:
        author = "Elastic Security"
        id = "66c465a0-821d-43ea-82f5-fe787720bfbf"
        fingerprint = "e26071afff71506236b261a44e8f1903d348dd33b95597458649f377710492f4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "7454ee074812d7fa49044de8190e17b5034b3f08625f547d1b04aae4054fd81a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 75 E6 B2 07 FE C0 EB DE 83 EC 10 6A 00 6A 00 6A 00 6A 00 FF 74 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_d8573802 {
    meta:
        author = "Elastic Security"
        id = "d8573802-f141-4fd1-b06a-605451a72465"
        fingerprint = "0052566dda66ae0dfa54d68f4ce03b5a2e2a442c4a18d70f16fd02303a446e66"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "7454ee074812d7fa49044de8190e17b5034b3f08625f547d1b04aae4054fd81a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 40 74 38 51 51 6A 02 FF 74 24 18 FF 93 C8 00 00 00 83 C4 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_7926bc8e {
    meta:
        author = "Elastic Security"
        id = "7926bc8e-110f-4b8a-8cc5-003732b6fcfd"
        fingerprint = "246e06d73a3a61ade6ac5634378489890a5585e84be086e0a81eb7586802e98f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "555d60bd863caff231700c5f606d0034d5aa8362862d1fd0c816615d59f582f7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { ED 74 31 48 8B 5B 10 4A 8D 6C 3B FC 48 39 EB 77 23 8B 3B 48 83 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_e2377400 {
    meta:
        author = "Elastic Security"
        id = "e2377400-8884-42fb-b524-9cdf836dac3a"
        fingerprint = "531a8fcb1c097f72cb9876a35ada622dd1129f90515d84b4c245920602419698"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "b88daf00a0e890b6750e691856b0fe7428d90d417d9503f62a917053e340228b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EC 08 8B 5C 24 10 8B 43 20 85 C0 74 72 83 7B 28 00 74 6C 83 7B }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_994f1e97 {
    meta:
        author = "Elastic Security"
        id = "994f1e97-c370-4eb2-ac93-b5ebf112f55d"
        fingerprint = "6cc0ace6beb6c1bf4e10f9781bb551c10f48cc23efe9529d92b432b0ff88f245"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C6 44 24 16 68 C6 44 24 15 63 C6 44 24 14 74 C6 44 24 13 61 C6 44 24 12 77 C6 44 24 11 2F C6 44 24 10 76 C6 44 24 0F 65 C6 44 24 0E 64 C6 44 24 0D 2F }
    condition:
        all of them
}

