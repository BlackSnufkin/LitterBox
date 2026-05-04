rule Linux_Trojan_Sdbot_98628ea1 {
    meta:
        author = "Elastic Security"
        id = "98628ea1-40d8-4a05-835f-a5a5f83637cb"
        fingerprint = "15cf6b916dd87915738f3aa05a2955c78a357935a183c0f88092d808535625a5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sdbot"
        reference_sample = "5568ae1f8a1eb879eb4705db5b3820e36c5ecea41eb54a8eef5b742f477cbdd8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 00 3C 08 54 00 02 00 26 00 00 40 4D 08 00 5C 00 50 00 49 00 }
    condition:
        all of them
}

