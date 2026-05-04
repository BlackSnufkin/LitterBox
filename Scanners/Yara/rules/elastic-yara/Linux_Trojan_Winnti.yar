rule Linux_Trojan_Winnti_61215d98 {
    meta:
        author = "Elastic Security"
        id = "61215d98-f52d-45d3-afa2-4bd25270aa99"
        fingerprint = "20ee92147edbf91447cca2ee0c47768a50ec9c7aa7d081698953d3bdc2a25320"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Winnti"
        reference_sample = "cc1455e3a479602581c1c7dc86a0e02605a3c14916b86817960397d5a2f41c31"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF FF FF C9 C3 55 48 89 E5 48 83 EC 30 89 F8 66 89 45 DC C7 45 FC FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_4c5a1865 {
    meta:
        author = "Elastic Security"
        id = "4c5a1865-ff41-445b-8616-c83b87498c2b"
        fingerprint = "685fe603e04ff123b3472293d3d83e2dc833effd1a7e6c616ff17ed61df0004c"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Winnti"
        reference = "0d963a713093fc8e5928141f5747640c9b43f3aadc8a5478c949f7ec364b28ad"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C1 E8 1F 84 C0 75 7B 85 D2 89 D5 7E 75 8B 47 0C 39 C6 7D 6E 44 8D }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_6f4ca425 {
    meta:
        author = "Elastic Security"
        id = "6f4ca425-5cd2-4c22-b017-b5fc02b3abc2"
        fingerprint = "dec25af33fc004de3a1f53e0c3006ff052f7c51c95f90be323b281590da7d924"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Winnti"
        reference = "161af780209aa24845863f7a8120aa982aa811f16ec04bcd797ed165955a09c1"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 89 7D D8 48 8B 45 D8 0F B6 40 27 0F BE C0 89 45 F8 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_de4b0f6e {
    meta:
        author = "Elastic Security"
        id = "de4b0f6e-0183-4ea8-9c03-f716a25f1884"
        fingerprint = "c72eddc2d72ea979ad4f680d060aac129f1cd61dbdf3b0b5a74f5d35a9fe69d7"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Winnti"
        reference = "a6b9b3ea19eaddd4d90e58c372c10bbe37dbfced638d167182be2c940e615710"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 85 30 FF FF FF 02 00 48 8D 85 30 FF FF FF 48 8D 50 02 0F B7 85 28 FF }
    condition:
        all of them
}

