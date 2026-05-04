rule Linux_Trojan_Morpes_d2ae1edf {
    meta:
        author = "Elastic Security"
        id = "d2ae1edf-7dd3-4506-96e0-039c8f00d688"
        fingerprint = "a4cedb0ef6c9c5121ee63c0c8f6bb8072f62b5866c916c7000d94999cd61b9b5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Morpes"
        reference_sample = "14c4c297388afe4be47be091146aea6c6230880e9ea43759ef29fc1471c4b86b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 64 B0 05 00 00 B0 05 00 00 B0 05 00 00 3C 00 00 00 3C 00 00 00 }
    condition:
        all of them
}

