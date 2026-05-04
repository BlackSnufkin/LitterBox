rule Linux_Hacktool_Tcpscan_334d0ca5 {
    meta:
        author = "Elastic Security"
        id = "334d0ca5-d143-4a32-8632-9fbdd2d96987"
        fingerprint = "1f8fc064770bd76577b9455ae858d8a98b573e01a199adf2928d8433d990eaa7"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Tcpscan"
        reference_sample = "62de04185c2e3c22af349479a68ad53c31b3874794e7c4f0f33e8d125c37f6b0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C4 10 89 45 D4 83 7D D4 00 79 1A 83 EC 0C 68 13 }
    condition:
        all of them
}

