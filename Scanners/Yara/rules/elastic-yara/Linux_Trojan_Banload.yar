rule Linux_Trojan_Banload_d5e1c189 {
    meta:
        author = "Elastic Security"
        id = "d5e1c189-7d19-4f03-a4f3-a0aaf6d499dc"
        fingerprint = "4aa04f08005b1b7ed941dbfc563737728099e35e3f0f025532921b91b79c967c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Banload"
        reference_sample = "48bf0403f777db5da9c6a7eada17ad4ddf471bd73ea6cf02817dd202b49204f4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E4 E4 E4 58 88 60 90 E4 E4 E4 E4 68 98 70 A0 E4 E4 E4 E4 78 }
    condition:
        all of them
}

