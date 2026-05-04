rule Linux_Trojan_Torii_fa253f2a {
    meta:
        author = "Elastic Security"
        id = "fa253f2a-d1a5-48b0-a3d6-aba06231e1ed"
        fingerprint = "fddf2a12f09add31fffc6b11bb3fe9e0666dae57ac8cef4dbbdee58f66df2c0a"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Torii"
        reference_sample = "19004f250b578b3b53273e8426285df2030fac0aee3227ef98e7fcbf2a8acb86"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 69 6D 65 00 47 4C 49 42 43 5F 32 2E 31 34 00 47 4C 49 42 43 5F }
    condition:
        all of them
}

