rule Linux_Ransomware_Hive_bdc7de59 {
    meta:
        author = "Elastic Security"
        id = "bdc7de59-bf12-461f-99e0-ec2532ace4e9"
        fingerprint = "415ef589a1c2da6b16ab30fb68f938a9ee7917f5509f73aa90aeec51c10dc1ff"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Ransomware.Hive"
        reference_sample = "713b699c04f21000fca981e698e1046d4595f423bd5741d712fd7e0bc358c771"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 40 03 4C 39 C1 73 3A 4C 89 84 24 F0 00 00 00 48 89 D3 48 89 CF 4C }
    condition:
        all of them
}

