rule Linux_Trojan_Mechbot_f2e1c5aa {
    meta:
        author = "Elastic Security"
        id = "f2e1c5aa-3318-4665-bee4-34a4afcf60bd"
        fingerprint = "4b663b0756f2ae9b43eae29cd0225ad75517ef345982e8fdafa61f3c3db2d9f5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mechbot"
        reference_sample = "5f8e80e6877ff2de09a12135ee1fc17bee8eb6d811a65495bcbcddf14ecb44a3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 52 56 45 52 00 42 41 4E 4C 49 53 54 00 42 4F 4F 54 00 42 }
    condition:
        all of them
}

