rule Linux_Ransomware_Clop_728cf32a {
    meta:
        author = "Elastic Security"
        id = "728cf32a-94c1-4979-b092-6851649946be"
        fingerprint = "86644f9f1e9f0b69896cd05ae1442a3b99483cc0ff15773c0c3403e59b6d5c97"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Clop"
        reference_sample = "09d6dab9b70a74f61c41eaa485b37de9a40c86b6d2eae7413db11b4e6a8256ef"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "CONTACT US BY EMAIL:"
        $a2 = "OR WRITE TO THE CHAT AT->"
        $a3 = "(use TOR browser)"
        $a4 = ".onion/"
    condition:
        3 of them
}

