rule Windows_Ransomware_Phobos_a5420148 : beta {
    meta:
        author = "Elastic Security"
        id = "a5420148-2f80-4a14-8a0d-98943fcbe784"
        fingerprint = "2b3937dbecb9a12e5e276c681eb40cb3884411a048175fcfe1bd4be3f7611aca"
        creation_date = "2020-06-25"
        last_modified = "2021-08-23"
        description = "Identifies Phobos ransomware"
        threat_name = "Windows.Ransomware.Phobos"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 61 00 63 00 75 00 74 00 65 00 00 00 61 00 63 00 74 00 69 00 6E 00 00 00 61 00 63 00 74 00 6F 00 6E 00 00 00 61 00 63 00 74 00 6F 00 72 00 00 00 61 00 63 00 75 00 66 00 66 00 00 }
        $a2 = { 0C 6D 00 73 00 66 00 74 00 65 00 73 00 71 00 6C 00 2E 00 65 00 78 00 65 00 00 00 73 00 71 00 6C 00 61 00 67 00 65 00 6E 00 74 00 2E 00 65 00 78 00 65 00 00 00 73 00 71 00 6C 00 62 00 72 00 6F 00 77 00 73 00 65 00 72 00 2E 00 65 00 78 00 65 00 00 00 73 00 71 00 6C 00 73 00 65 00 72 00 76 00 72 00 2E 00 65 00 78 00 65 00 00 00 73 00 71 00 6C 00 77 00 72 00 69 00 74 00 65 00 72 00 2E 00 65 00 78 00 65 00 00 00 6F 00 72 00 61 00 63 00 6C 00 65 00 2E 00 65 00 78 00 }
        $a3 = { 31 00 63 00 64 00 00 00 33 00 64 00 73 00 00 00 33 00 66 00 72 00 00 00 33 00 67 00 32 00 00 00 33 00 67 00 70 00 00 00 37 00 7A 00 00 00 61 00 63 00 63 00 64 00 61 00 00 00 61 00 63 00 63 00 64 00 62 00 00 00 61 00 63 00 63 00 64 00 63 00 00 00 61 00 63 00 63 00 64 00 65 00 00 00 61 00 63 00 63 00 64 00 74 00 00 00 61 00 63 00 63 00 64 00 77 00 00 00 61 00 64 00 62 00 00 00 61 00 64 00 70 00 00 00 61 00 69 00 00 00 61 00 69 00 33 00 00 00 61 00 69 00 34 00 00 00 61 00 69 00 35 00 00 00 61 00 69 00 36 00 00 00 61 00 69 00 37 00 00 00 61 00 69 00 38 00 00 00 61 00 6E 00 69 00 6D 00 00 00 61 00 72 00 77 00 00 00 61 00 73 00 00 00 61 00 73 00 61 00 00 00 61 00 73 00 63 00 00 00 61 00 73 00 63 00 78 00 00 00 61 00 73 00 6D 00 00 00 61 00 73 00 6D 00 78 00 00 00 61 00 73 00 70 00 00 00 61 00 73 00 70 00 78 00 00 00 61 00 73 00 72 00 00 00 61 00 73 00 78 00 00 00 61 00 76 00 69 00 00 00 61 00 76 00 73 00 00 00 62 00 61 00 63 00 6B 00 75 00 70 00 00 00 62 00 61 00 6B 00 00 00 62 00 61 00 79 00 00 00 62 00 64 00 00 00 62 00 69 00 6E 00 00 00 62 00 6D 00 70 00 00 00 }
    condition:
        2 of ($a*)
}

rule Windows_Ransomware_Phobos_ff55774d : beta {
    meta:
        author = "Elastic Security"
        id = "ff55774d-4425-4243-8156-ce029c1d5860"
        fingerprint = "d8016c9be4a8e5b5ac32b7108542fee8426d65b4d37e2a9c5ad57284abb3781e"
        creation_date = "2020-06-25"
        last_modified = "2021-08-23"
        description = "Identifies Phobos ransomware"
        threat_name = "Windows.Ransomware.Phobos"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
        severity = 90
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $c1 = { 24 18 83 C4 0C 8B 4F 0C 03 C6 50 8D 54 24 18 52 51 6A 00 6A 00 89 44 }
    condition:
        1 of ($c*)
}

rule Windows_Ransomware_Phobos_11ea7be5 : beta {
    meta:
        author = "Elastic Security"
        id = "11ea7be5-7aac-41d7-8d09-45131a9c656e"
        fingerprint = "a264f93e085134e5114c5d72e1bf93e70935e33756a79f1021e9c1e71d6c8697"
        creation_date = "2020-06-25"
        last_modified = "2021-08-23"
        description = "Identifies Phobos ransomware"
        threat_name = "Windows.Ransomware.Phobos"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $b1 = { C0 74 30 33 C0 40 8B CE D3 E0 85 C7 74 19 66 8B 04 73 66 89 }
    condition:
        1 of ($b*)
}

