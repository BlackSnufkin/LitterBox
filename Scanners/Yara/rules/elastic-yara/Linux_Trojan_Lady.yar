rule Linux_Trojan_Lady_75f6392c {
    meta:
        author = "Elastic Security"
        id = "75f6392c-fc13-4abb-a391-b5f1ea1039d8"
        fingerprint = "da6d4dff230120eed94e04b0e6060713c2bc17da54c098e9a9f3ec7a8200b9bf"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Lady"
        reference_sample = "c257ac7bd3a9639e0d67a7db603d5bc8d8505f6f2107a26c2615c5838cf11826"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 57 72 69 00 49 3B 66 10 76 38 48 83 EC 18 48 89 6C 24 10 48 8D 6C }
    condition:
        all of them
}

