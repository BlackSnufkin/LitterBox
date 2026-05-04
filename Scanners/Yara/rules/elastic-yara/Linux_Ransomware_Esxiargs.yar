rule Linux_Ransomware_Esxiargs_75a8ec04 {
    meta:
        author = "Elastic Security"
        id = "75a8ec04-c41d-4702-94fa-976870762aaf"
        fingerprint = "279259c7ca41331b09842c2221139d249d6dfe2e2cb6b27eb50af7be75120ce4"
        creation_date = "2023-02-09"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Esxiargs"
        reference_sample = "11b1b2375d9d840912cfd1f0d0d04d93ed0cddb0ae4ddb550a5b62cd044d6b66"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $s1 = "number of MB in encryption block"
        $s2 = "number of MB to skip while encryption"
        $s3 = "get_pk_data: key file is empty"
        $s4 = { 6F 70 65 6E 00 6C 73 65 65 6B 20 5B 65 6E 64 5D 00 6F 70 65 6E 5F 70 6B 5F 66 69 6C 65 }
        $s5 = "[<enc_step>] [<enc_size>] [<file_size>]"
    condition:
        3 of them
}

