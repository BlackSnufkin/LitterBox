rule Linux_Trojan_Gognt_50c3d9da {
    meta:
        author = "Elastic Security"
        id = "50c3d9da-0392-4379-aafe-cfe63ade3314"
        fingerprint = "a4b7e0c7c2f1b0634f82106ec0625bcdde02296b3e72c9c3aa9c16e40d770b43"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gognt"
        reference_sample = "79602bc786edda7017c5f576814b683fba41e4cb4cf3f837e963c6d0d42c50ee"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 47 6F 00 00 51 76 46 5F 6F 30 59 36 55 72 5F 6C 63 44 }
    condition:
        all of them
}

rule Linux_Trojan_Gognt_05b10f4b {
    meta:
        author = "Elastic Security"
        id = "05b10f4b-7434-457a-9e8e-d898bb839dce"
        fingerprint = "fdf7b65f812c17c7f30b3095f237173475cdfb0c10a4b187f751c0599f6b5729"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gognt"
        reference_sample = "e43aaf2345dbb5c303d5a5e53cd2e2e84338d12f69ad809865f20fd1a5c2716f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 7C 24 78 4C 89 84 24 A8 00 00 00 48 29 D7 49 89 F9 48 F7 DF 48 C1 }
    condition:
        all of them
}

