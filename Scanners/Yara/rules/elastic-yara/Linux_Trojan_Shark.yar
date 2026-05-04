rule Linux_Trojan_Shark_b918ab75 {
    meta:
        author = "Elastic Security"
        id = "b918ab75-0701-4865-b798-521fdd2ffc28"
        fingerprint = "15205d58af99b8eae14de2d5762fdc710ef682839967dd56f6d65bd3deaa7981"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Shark"
        reference_sample = "8b6fe9f496996784e42b75fb42702aa47aefe32eac6f63dd16a0eb55358b6054"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 26 00 C7 46 14 0A 00 00 00 C7 46 18 15 00 00 00 EB 30 C7 46 14 04 00 }
    condition:
        all of them
}

