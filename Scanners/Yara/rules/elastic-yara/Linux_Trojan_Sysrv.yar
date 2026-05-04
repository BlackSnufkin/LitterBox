rule Linux_Trojan_Sysrv_85097f24 {
    meta:
        author = "Elastic Security"
        id = "85097f24-2e2e-41e4-8769-dca7451649cc"
        fingerprint = "1cad651c92a163238f8d60d2e3670f229b4aafd6509892b9dcefe014b39c6f7d"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sysrv"
        reference = "17fbc8e10dea69b29093fcf2aa018be4d58fe5462c5a0363a0adde60f448fb26"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 32 26 02 0F 80 0C 0A FF 0B 02 02 22 04 2B 02 16 02 1C 01 0C 09 }
    condition:
        all of them
}

